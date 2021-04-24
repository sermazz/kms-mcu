#include <stdio.h>
#include <stdint.h>
// For trace_printf
#include "diag/Trace.h"
// My libraries
#include <time_handler.h>
#include <kms.h>
#include <nv_mem.h>
// Computational functions libraries
#include <aes256.h>
#include <hmac_sha256.h>

/*
 * KEY MANAGEMENT SYSTEM LIBRARY
 * -----------------------------
 * Implementation of the library defined in kms.h
 *
 */

/************************************* DEFINES *************************************/

#define __VERBOSE  /* Enable verbose trace_printf KMS interface errors*/


/************************************ CONSTANTS ************************************/

/* Empty key structure, useful to completely delete previously valid keys */
const struct kms_key kms_empty_record = {
	0,  // key id
	0,  // key size
	KMS_KEY_EMPTY,  // key state
	0, // cryptopperiod
	0, // key expire time
	{  // key content
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};


/************************************ VARIABLES ************************************/

/*
 * It is useful to know how many keys are stored in the KMS database in order to stop
 * a search process when such number is reached, so that it is not necessary to scan
 * the whole memory in search of a key. This is particularly useful because, even if
 * an entry is empty (not containing a key, i.e. SIZE field of header is empty), you
 * have to go on comparing next entries: an empty entry indeed only means that a
 * previously available key has now been removed, and not that the KMS database
 * terminates at that address.
 */
uint32_t keys_num;	/* To keep track of number of stored keys in KMS */


/****************************** FUNCTIONS DEFINITIONS ******************************/


/* ------------------------------------------------------------------------------- */
/* ------------------------- KMS main functionalities ---------------------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function kms_init
 * -----------------
 * Initialize Key Management System at boot up, basing on whether the non-volatile
 * memory has just been initialized for the first time (just initialized and empty)
 * or it already existed with useful values in it, which do not need initialization.
 * It returns: 0 in case of success, -1 otherwise.
 */
int kms_init(nvm_init_t nvm_init){
	int ret;

	switch(nvm_init){
		case NVM_NO_FIRST_INIT:
			// Retrieve number of available keys from non-volatile memory
			ret = read_nvm(KMS_KEYS_NUM_REG_BASE, &keys_num, sizeof(uint32_t));
			if (ret){
				#ifdef __VERBOSE
				trace_printf("ERROR: (kms - 1.1) Error @ read_nvm in kms_init.\n");
				#endif
				return -1;
			}
			break;

		case NVM_FIRST_INIT:
			// First time dealing with KMS, no keys in it: must initialize keys_num to 0
			keys_num = 0;
			ret = write_nvm(KMS_KEYS_NUM_REG_BASE, &keys_num, sizeof(uint32_t));
			if (ret){
				#ifdef __VERBOSE
				trace_printf("ERROR: (kms - 1.2) Error @ write_nvm in kms_init.\n");
				#endif
				return -1;
			}
			break;

		case NVM_INIT_ERROR:
			// Error in memory initialization: KMS cannot be initialized
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 1.3) Error @ \"case NVM_INIT_ERROR\" in kms_init.\n");
			#endif
			return -1;
			break;
	}

	return 0;  // success
}

/*
 * Function kms_add_key
 * --------------------
 * Add a key record with fields specified by input arguments in the first empty
 * record found in the KMS database stored in the Flash memory; the actual content of
 * the key field of the new KMS record is encrypted before being stored in the Flash
 * memory. The key is obtained by hashing the seed provided as input.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: no space left to add a new key
 *            -2 -> WARNING: error in key gen (seed too small or encrypted key too big)
 *            -3 -> WARNING: key with given key_id already present in KMS database
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_add_key(uint32_t key_id, uint16_t key_size, uint8_t* seed, uint16_t seed_size, uint32_t cryptoperiod){
	struct kms_key new_key;
	kms_index_t    record_index;
	int            ret;

	// Check if key with given id already exists
	ret = kms_search_key(key_id, &record_index);
	if (ret > 0){
		// if key with this id already exists
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 2.1) Error @ kms_search_key in kms_add_key.\n");
		#endif
		return -3; // warning: key_id already exists
	}
	else if (ret < 0) {
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 2.2) Error @ kms_search_key in kms_add_key.\n");
		#endif
		return -1;
	}

	// If here, no key w/ the given ID has been found, ok!
	// Search for an empty record where to write new key
	ret = kms_search_empty_record(&record_index);
	if (ret == 0){
		// no empty space left, return warning
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 2.3) Error @ kms_search_empty_record in kms_add_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 2.4) Error @ kms_search_empty_record in kms_add_key.\n");
		#endif
		return -1;
	}

	// Key record content definition
	new_key.id = key_id;
	new_key.size = key_size;
	new_key.state = KMS_KEY_PREACTIVE;	// default state for every new key
	new_key.cryptoperiod = cryptoperiod;
	new_key.expire_time = 0;
	
	ret = generate_key(seed, seed_size, new_key.key, key_size);
	if (ret){
		// Warning: error in key generation
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 2.5) Error @ generate_key in kms_add_key.\n");
		#endif
		return -2;  // warning for problem in key gen
	}
	// Write key struct in empty record
	ret = write_nvm(KMS_DB(record_index), (void*)&new_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 2.6) Error @ write_nvm in kms_add_key.\n");
		#endif
		return -1;
	}
	// Increase by 1 the number of VALID keys in the KSM database
	ret = kms_keys_num_update(KMS_KEYS_NUM_UPDATE_INCR);
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 2.7) Error @ kms_keys_num_update in kms_add_key.\n");
		#endif
		return -1;
	}

	return 1;  // success
}

/*
 * Function kms_remove_key
 * -----------------------
 * Set as EMPTY the key record in the KMS database identified by the given id; the
 * content of all fields of the deleted records are also overwritten with zeros so
 * that tracks of old keys are not left in the memory.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: key not found in KMS database
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_remove_key(uint32_t key_id){
	kms_index_t key_index;
	int ret;

	// Search for KMS database index of key corresponding to given id
	ret = kms_search_key(key_id, &key_index);
	if (ret == 0){
		// key id not found
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 3.1) Error @ kms_search_key in kms_remove_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 3.2) Error @ kms_search_key in kms_remove_key.\n");
		#endif
		return -1;
	}

	// Overwrite with empty KMS key structure
	ret = write_nvm(KMS_DB(key_index), (void*)&kms_empty_record, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 3.3) Error @ write_nvm in kms_remove_key.\n");
		#endif
		return -1;
	}
	// Decrease by 1 the number of VALID keys in KMS database
	ret = kms_keys_num_update(KMS_KEYS_NUM_UPDATE_DECR);
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 3.4) Error @ kms_keys_num_update in kms_remove_key.\n");
		#endif
		return -1;
	}

	return 1;  // success
}

/*
 * Function kms_update_key
 * -----------------------
 * Update an already present and valid key in the KMS database by providing a new
 * seed for a new key generation procedure. This function is only meant to RE-SEED
 * an existing key without changing its key_size.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: key not found in KMS database
 *            -2 -> WARNING: error in key gen (seed too small or encrypted key too big)
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_update_key(uint32_t key_id, uint8_t* seed, uint16_t seed_size, uint32_t cryptoperiod){
	struct kms_key upd_key;
	kms_index_t    key_index;
	int            ret;

	// Search for KMS database index of key corresponding to given id
	ret = kms_search_key(key_id, &key_index);
	if (ret == 0){
		// key id not found
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 4.1) Error @ kms_search_key in kms_update_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 4.2) Error @ kms_search_key in kms_update_key.\n");
		#endif
		return -1;
	}

	// Read key struct from Flash memory pointed by found index
	ret = read_nvm(KMS_DB(key_index), (void*)&upd_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 4.3) Error @ read_nvm in kms_update_key.\n");
		#endif
		return -1;
	}

	// New key generation, with same size but new seed
	ret = generate_key(seed, seed_size, upd_key.key, upd_key.size);
	if (ret){
		// warning for error in key gen
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 4.4) Error @ generate_key in kms_update_key.\n");
		#endif
		return -2;
	}

	upd_key.cryptoperiod = cryptoperiod;
	upd_key.expire_time = 0;
	// An updated key defaults to the PREACTIVE state, no matter the original state
	upd_key.state = KMS_KEY_PREACTIVE;
	// Update key in KMS storage
	ret = write_nvm(KMS_DB(key_index), (void*)&upd_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 4.5 Error @ write_nvm in kms_update_key.\n");
		#endif
		return -1;
	}

	return 1;  // success
}

/*
 * Function kms_get_key
 * --------------------
 * Look in the KMS DB for the key specified by the given id input argument and, if
 * found, store it in the structure pointed by key_p, with the key content field
 * decrypted before returning it to the caller.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: key not found in KMS database
 *            -1 -> ERROR: an hard fault occurs
 *            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
 *            -3 -> WARNING: transition NOT permitted
 *            -4 -> WARNING: glitch has occurred in a ret value
 */
int kms_get_key(uint32_t key_id, struct kms_key* key_p){
	kms_index_t key_index;
	struct kms_key got_key;
	int encrypted_key_size;
	int ret;

	// Search for KMS database index of key corresponding to given id
	ret = kms_search_key(key_id, &key_index);
	if (ret == 0){
		// key id not found
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 5.1) Error @ kms_search_key in kms_get_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 5.2) Error @ kms_search_key in kms_get_key.\n");
		#endif
		return -1;
	}

	// Read key struct from Flash memory pointed by found index
	ret = read_nvm(KMS_DB(key_index), (void*)&got_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 5.3) Error @ read_nvm in kms_get_key.\n");
		#endif
		return -1;
	}

	ret = kms_check_expire_time(&got_key);
	if (ret == -1) {
		// ERROR: an hard fault occurs
		// Error while getting actual time, abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 5.4) Error @ kms_check_expire_time in kms_get_key.\n");
		#endif
		return -1;
	}
	else if (ret == 1) {
		// The key is NO MORE VALID, further action is required
		// We must set its state to "Deactivated"
		ret = key_state_transition(&got_key, KMS_KEY_DEACTIVATED);
		if (ret == -2) {
			// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
			#ifdef __VERBOSE
			trace_printf("WARNING: (kms - 5.5) Error @ key_state_transition in kms_get_key.\n");
			#endif
			// Set the key to compromised for precaution
			got_key.state = KMS_KEY_COMPROMISED;
			return -2;
		}
		else if (ret == 0) {
			// WARNING: transition NOT permitted
			// The user is asking to do an encryption/decryption/hmac using a key that wasn't neither active nor suspended
			// The caller function will notify the user that the command cannot be completed
			#ifdef __VERBOSE
			trace_printf("WARNING: (kms - 5.6) Error @ key_state_transition in kms_get_key.\n");
			#endif
			return -3;
		}
		else if (ret != 1) {
			// External Glitching attempt affecting the return code
			#ifdef __VERBOSE
			trace_printf("WARNING: (kms - 5.7) Error @ key_state_transition in kms_get_key.\n");
			#endif
			// Set the key to compromised for precaution
			got_key.state = KMS_KEY_COMPROMISED;
			return -4;
		}

		// If here, the transition is allowed and the key is now DEACTIVATED
		// Update key in KMS storage
		ret = write_nvm(KMS_DB(key_index), (void*)&got_key, sizeof(struct kms_key));
		if (ret){
			// return error and abort
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 5.8) Error @ write_nvm in kms_get_key.\n");
			#endif
			return -1;
		}
		// We can continue below, the key can still be used for DECRYPTION
	}

	// If here, the key HAS NOT EXPIRED YET (Active/Suspended) or is now DEACTIVATED

	// Write output structure pointed by key_p
	/*
	 * Due to the key being encrypted with AES-256, for decryption we must take from
	 * got_key.key a number of bytes which is not got_key.size, but its nearest and
	 * greater multiple of AES_BLOCK_SIZE. The array of such size, which should not
	 * be in any case longer than MAX_KEY_SIZE bytes, can be correctly decrypted into
	 * an array also containing the padding added by the AES-256 algorithm, but which
	 * will be correctly excluded from the key due to our knowledge of the original
	 * size of the key, stored in got_key.size
	 */
	// nearest equal of greatest multiple of AES_BLOCK_SIZE wrt to got_key.size
	encrypted_key_size = (got_key.size - 1)/AES_BLOCK_SIZE * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
	if (encrypted_key_size > MAX_KEY_SIZE){
		// should never happen if key is correctly stored in KMS
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 5.9) Error @ encrypted_key_size > MAX_KEY_SIZE in kms_get_key (too large encrypted key of %d bytes).\n", encrypted_key_size);
		#endif
		return -1;  // error (should never happen)
	}
	decrypt_cbc((char*)got_key.key, encrypted_key_size, (char*)AES_KMS_KEY, (char*)key_p->key);

	key_p->id = got_key.id;
	key_p->size = got_key.size;
	key_p->state = got_key.state;
	key_p->cryptoperiod = got_key.cryptoperiod;
	key_p->expire_time = got_key.expire_time;

	return 1;  // success
}

/*
 * Function kms_list_key
 * ---------------------
 * Scans the KMS database memory in saerch of all existing VALID keys, and stores
 * their IDs in the array pointed by input argument valid_keys_id; note that such
 * array must be able to store up to MAX_KEYS_NUM uint32_t variables, which is the
 * maximum number of keys which can be allocated in a database size given by KMS_DB_LIMIT
 * (i.e. in the non-volatile memory region starting from byte of address KMS_DB_BASE,
 * and with a size of KMS_DB_LIMIT)
 * It returns: >0 -> in case of success, specifies number of VALID keys in KMS database
 *              0 -> no VALID keys in KMS database (database empty)
 *             -1 -> ERROR: an hard fault occurs (non-volatile memory or keys num fault)
 */
int kms_list_key(uint32_t* valid_keys_id){
	struct kms_key key_test;
	nvm_address_t next_key_addr;
	int ret;
	uint32_t tested_keys = 0;


	/*
	 * Scan whole memory or until keys_num VALID keys are tested, reporting in the
	 * array valid_keys_id the id of the encountered VALID keys
	 */

	// Scan whole database in Flash memory
	for (kms_index_t i = 0; KMS_DB(i) + sizeof(struct kms_key) < KMS_DB_BASE + KMS_DB_LIMIT; i++){

		// If reached number of VALID keys in KMS DB (no more VALID records after)
		if (tested_keys >= keys_num)
			// all records with a VALID key have been traversed
			break;

		// Extract new key
		next_key_addr = KMS_DB(i);
		ret = read_nvm(next_key_addr, (void*)&key_test, sizeof(struct kms_key));
		if (ret){
			// return error and abort
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 6.1) Error @ read_nvm in kms_list_key.\n");
			#endif
			return -1;
		}

		// If key is VALID (i.e. it can be in all states but KMS_EMPTY)
		if (key_test.state != KMS_KEY_EMPTY) {
			*(valid_keys_id + tested_keys) = key_test.id;
			// Increase number of valid keys tested
			tested_keys++;
		}
	}
	// This check should be true, otherwise something wrong happened previously
	if (tested_keys != keys_num){
		// this scenario cannot be managed, hard fault: return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 6.2) Error @ \"tested_keys != keys_num\" in kms_list_key.\n");
		#endif
		return -1;
	}
	return keys_num; // success
}

/*
 * Function kms_change_status_key
 * ------------------------------
 * Change the current status of the key, i.e. this function implements all possible (and allowed)
 * transitions of the state graph
 * It returns: 1 -> in case of success
 *             0 -> WARNING: key not found in KMS database
 *            -1 -> ERROR: an hard fault occurs
 *            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
 *            -3 -> WARNING: transition NOT permitted
 *            -4 -> WARNING: glitch has occurred in a ret value
 *            -5 -> WARNING: transition is a loop
 */
int kms_change_status_key(uint32_t key_id, key_state_t end_state){
	struct kms_key upd_key;
	kms_index_t    key_index;
	key_state_t    start_state;
	int            ret;

	// Search for KMS database index of key corresponding to given id
	ret = kms_search_key(key_id, &key_index);
	if (ret == 0){
		// key id not found
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 7.1) Error @ kms_search_key in kms_change_status_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 7.2) Error @ kms_search_key in kms_change_status_key.\n");
		#endif
		return -1;
	}

	// Read key struct from Flash memory pointed by found index
	ret = read_nvm(KMS_DB(key_index), (void*)&upd_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 7.3) Error @ read_nvm in kms_change_status_key.\n");
		#endif
		return -1;
	}

	// Save the current state of the key before changing it, will be used next
	start_state = upd_key.state;

	// Check if the transition is permitted and, if so, complete it
	ret = key_state_transition(&upd_key, end_state);
	if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 7.4) Error @ key_state_transition in kms_change_status_key.\n");
		#endif
		// Set the key to compromised for precaution
		upd_key.state = KMS_KEY_COMPROMISED;
		return -2;
	}
	else if (ret == 0) {
		// WARNING: transition NOT permitted
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 7.5) Error @ key_state_transition in kms_change_status_key.\n");
		#endif
		return -3;
	}
	else if (ret != 1) {
		// External Glitching attempt affecting the return code
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 7.6) Error @ key_state_transition in kms_change_status_key.\n");
		#endif
		// Set the key to compromised for precaution
		upd_key.state = KMS_KEY_COMPROMISED;
		return -4;
	}

	#ifdef __VERBOSE
	trace_printf("MESSAGE: (kms - 7.7) Key status transition completed in kms_change_status_key.\n");
	#endif

	// If here, transition has been done
	// Depending on the new key state, we may need to complete some additional work
	if (start_state == KMS_KEY_PREACTIVE && upd_key.state == KMS_KEY_ACTIVE) {
		// The expire_time of the key is computed upon activation
		uint32_t current_time = get_time();
		if (current_time == 0) {
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 7.8) Error @ get_time in kms_change_status_key.\n");
			#endif
			return -1; // hard fault, abort
		}
		else {
			upd_key.expire_time = upd_key.cryptoperiod + current_time;
			#ifdef __VERBOSE
			trace_printf("MESSAGE: (kms - 7.9) Expire time computed in kms_change_status_key.\n");
			#endif
		}
	}
	
	// Update key in KMS storage
	ret = write_nvm(KMS_DB(key_index), (void*)&upd_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 7.10) Error @ write_nvm in kms_change_status_key.\n");
		#endif
		return -1;
	}

	return 1;  // success
}

/*
 * Function kms_add_plain_key
 * --------------------------
 * Add a key record with fields specified by input arguments in the first empty
 * record found in the KMS database stored in the Flash memory; the actual content of
 * the key field of the new KMS record is encrypted before being stored in the Flash
 * memory. The actual key is not generated from a seed but used as provided directly
 * from the input argument.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: no space left to add a new key
 *            -2 -> WARNING: key with given key_id already present in KMS database
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_add_plain_key(uint32_t key_id, uint16_t key_size, uint8_t* key, uint32_t cryptoperiod){
	struct kms_key new_key;
	kms_index_t    record_index;
	int            ret;

	// Check if key with given id already exists
	ret = kms_search_key(key_id, &record_index);
	if (ret){
		// if key with this id already exists
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 8.1) Error @ kms_search_key in kms_add_plain_key.\n");
		#endif
		return -2; // warning: key_id already exists
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 8.2) Error @ kms_search_key in kms_add_plain_key.\n");
		#endif
		return -1;
	}

	// Search for an empty record where to write new key
	ret = kms_search_empty_record(&record_index);
	if (ret == 0){
		// no empty space left, return warning
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 8.3) Error @ kms_search_empty_record in kms_add_plain_key.\n");
		#endif
		return 0;
	}
	else if (ret < 0){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 8.4) Error @ kms_search_empty_record in kms_add_plain_key.\n");
		#endif
		return -1;
	}

	// Key record content definition
	new_key.id = key_id;
	new_key.size = key_size;
	new_key.state = KMS_KEY_PREACTIVE;	// default state for every new key
	new_key.cryptoperiod = cryptoperiod;
	new_key.expire_time = 0;

	// Encrypted the key from input arguments
	ret = encrypt_cbc((char*)key, key_size, (char*)AES_KMS_KEY, (char*)(new_key.key));
	if (ret > MAX_KEY_SIZE){
		// Encrypted key size is too big to be stored in key record structure kms_key
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 8.5) Error @ \"encrypt_cbc > MAX_KEY_SIZE\" in kms_add_plain_key (too large encrypted key of %d bytes).\n", ret);
		#endif
		return -1;
	}

	// Write key struct in empty record
	ret = write_nvm(KMS_DB(record_index), (void*)&new_key, sizeof(struct kms_key));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 8.6) Error @ write_nvm in kms_add_plain_key.\n");
		#endif
		return -1;
	}
	// Increase by 1 the number of VALID keys in the KSM database
	ret = kms_keys_num_update(KMS_KEYS_NUM_UPDATE_INCR);
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 8.7) Error @ kms_keys_num_update in kms_add_plain_key.\n");
		#endif
		return -1;
	}

	return 1;  // success
}


/* ------------------------------------------------------------------------------- */
/* --------------------------- Accessory functions ------------------------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function kms_search_key
 * -----------------------
 * Starting from KMS_DB_BASE address in Flash memory, this function scans the memory
 * as a fixed-records database, reading a (struct kms_key) at each iteration with the
 * aim to find the key with the id given by id input argument. If found, the database
 * index of the matching key is stored in the structure pointed by the pointer
 * key_index_p.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: key not found in KMS database
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_search_key(uint32_t key_id, kms_index_t* key_index_p){
	struct kms_key key_test;
	uint32_t tested_keys = 0;

	nvm_address_t next_key_addr;

	int ret;

	/*
	 * Scan whole Flash memory in search of key with given id: the memory is either
	 * traversed until the space allocated to the database end or the search stops when
	 * a number of VALID keys equal to the global variable keys_num (total VALID keys
	 * currently stored in KMS DB) have been tested (meaning that all available keys
	 * have been tested).
	 */

	// Scan whole database in Flash memory
	for (kms_index_t i = 0; KMS_DB(i) + sizeof(struct kms_key) < KMS_DB_BASE + KMS_DB_LIMIT; i++){

		// Break if reached number of VALID keys in KMS DB
		if (tested_keys >= keys_num)
			break;

		// Extract new key
		next_key_addr = KMS_DB(i);
		ret = read_nvm(next_key_addr, (void*)&key_test, sizeof(struct kms_key));
		if (ret){
			// return error and abort
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 9.1) Error @ read_nvm in kms_search_key.\n");
			#endif
			return -1;
		}

		if (key_test.state == KMS_KEY_EMPTY) {
			// Key is EMPTY
			continue;
		}
		else {
			// Key is VALID or DESTROYED
			if(key_test.id == key_id){
				#ifdef __VERBOSE
				trace_printf("MESSAGE: (kms - 9.2) Match found in kms_search_key for key ID#%u @ KMS index#%d.\n", key_id, i);
				#endif
				*key_index_p = i;
				return 1;  // match found
			} else {
				// Only increase number of NON-EMPTY keys tested
				tested_keys++;
			}
		}
	}
	// no match found
	#ifdef __VERBOSE
	trace_printf("MESSAGE: (kms - 9.3) No match found in kms_search_key for key ID#%u.\n", key_id);
	#endif
	return 0;
}

/**
 * @brief Given a key, this function checks if it still valid or not, by comparing its expire_time
 * parameter against the actual time.
 *
 * @param struct kms_key
 *
 * @return int
 * 0	--> OK, the key is STILL VALID, no further action required
 * 1	--> OK, the key is NO MORE VALID, further action is required form caller function
 * -1   --> hard fault, abort
 */
int kms_check_expire_time(struct kms_key *key){
	// Given the current KEY state, is it really necessary to check the expire time? 
	if (key->state == KMS_KEY_ACTIVE || key->state == KMS_KEY_SUSPENDED) {
		// Yes, the expire time must be checked
		uint32_t current_time = get_time();
		if (current_time == 0) {
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 10.1) Error @ get_time in kms_check_expire_time.\n");
			#endif
			return -1; // hard fault, abort
		}
		else if (current_time >= key->expire_time) {
			// The key is expired and hence NOT VALID ANYMORE, further action is required from caller function
			#ifdef __VERBOSE
			trace_printf("MESSAGE: (kms - 10.2) The key ID#%u has expired @ kms_check_expire_time.\n", key->id);
			#endif
			return 1;
		}
		else {
			// The key is NOT expired and hence STILL VALID, no further action required
			#ifdef __VERBOSE
			trace_printf("MESSAGE: (kms - 10.3) The key ID#%u has not expired yet @ kms_check_expire_time.\n", key->id);
			#endif
		}
	}
	// No, there's no need to check the expire time, further checks on the key state may be demanded outside this function
	return 0;
}

/*
 * Function kms_search_empty_record
 * --------------------------------
 * Starting from KMS_DB_BASE address in Flash memory, this function scans the memory
 * as a fixed-records database, reading a (struct kms_key) at each iteration with the
 * aim to find an empty record, useful to fill it with a valid key. If found before
 * the end of the database, the database index of the empty record is stored in the
 * structure pointed by the pointer empty_index_p.
 * It returns: 1 -> in case of success
 *             0 -> WARNING: no more empty space for new key records
 *            -1 -> ERROR: an hard fault occurs
 */
int kms_search_empty_record(kms_index_t* empty_index_p){
	struct kms_key key_test;
	uint32_t tested_keys = 0;

	nvm_address_t next_key_addr;

	int ret;

	/*
	 * Scan whole database in search of key record with EMPTY state: it may occur
	 * that either
	 * - the whole database is traversed until it ends: in that case no more space is
	 *   available, OR
	 * - the search stops when a number of VALID keys equal to the global variable
	 *   keys_num (total VALID keys currently stored in KMS DB) have been tested
	 *   (i.e. all available keys have been tested): it means that no empty records
	 *   have been found among VALID keys, and a new key will be written simply after
	 *   all the other key records OR
	 * - an EMPTY key record is found before the two previously described events
	 *   (i.e. a previously VALID key has been removed and left an empty record among
	 *   other VALID keys)
	 */

	// Scan whole database in Flash memory
	for (kms_index_t i = 0; KMS_DB(i) + sizeof(struct kms_key) < KMS_DB_BASE + KMS_DB_LIMIT; i++){

		// If reached number of VALID keys in KMS DB (no more VALID records after)
		if (tested_keys >= keys_num){
			// but further space available in database memory (we are sure of this because
			// KMS_DB(i) + sizeof(struct kms_key) < KMS_DB_BASE + KMS_DB_LIMIT condition is verified)
			#ifdef __VERBOSE
			trace_printf("MESSAGE: (kms - 11.1) Empty record found in kms_search_empty_record @ KMS index#%d.\n", i);
			#endif
			*empty_index_p = i;
			return 1;  // empty record found
		}
		// Extract new key
		next_key_addr = KMS_DB(i);
		ret = read_nvm(next_key_addr, (void*)&key_test, sizeof(struct kms_key));
		if (ret){
			// return error and abort
			#ifdef __VERBOSE
			trace_printf("ERROR: (kms - 11.2) Error @ read_nvm in kms_search_empty_record.\n");
			#endif
			return -1;  // error
		}

		/*
		 * With the following test we are sure not to read uninitialized random data
		 * because key are only managed with add/remove/update functions in this lib,
		 * and also we keep track of number of total VALID keys so that we know from
		 * which memory location on we are not sure anymore to find non-uninitialized
		 * random data.
		 * In other words, the following test is always meaningful thanks to the
		 * previously verified conditions of tested_keys >= keys_num and
		 * KMS_DB(i) + sizeof(struct kms_key) < KMS_DB_BASE + KMS_DB_LIMIT.
		 * 
		 * As this is programmed, only two scenarios are indeed possible:
		 * - a number of tested_keys equal to the current keys_num is traversed and checked
		 *   (before reaching the end of the KMS memory space) and no empty space is found
		 *   before: since the end of KMS is still not reached, it means there is more space
		 *   left after all the valid traversed keys, so directly write in that space without
		 *   having to read anything from that uninitialized space (because we are sure not
		 *   to overwrite any keys since we already reached tested_keys == keys_num)
		 * - an empty space is found (e.g. a key with state = KMS_KEY_EMPTY) before tested_keys
		 *   reaches keys_num, meaning that an hole has been found among other valid keys; this
		 *   means that a valid key was present in that hole but it has been explicitly removed
		 *   and thus the state has been explicitly set to KMS_KEY_EMPTY, which we discover by
		 *   reading the key structure (which is not random uninitialized data)
		 * This way of managing holes let us avoid to initialize the whole KMS memory to all
		 * zeros on the start-up of the device, which would be very inefficient, at the cost of
		 * maintaining the global variable keys_num and always updating it in the Flash memory.
		 */

		// If key is EMPTY
		if (key_test.state == KMS_KEY_EMPTY) {
			#ifdef __VERBOSE
			trace_printf("MESSAGE: (kms - 11.3) Empty record found in kms_search_empty_record @ KMS index#%d.\n", i);
			#endif
			*empty_index_p = i;
			return 1;  // empty record found
		} else {
			// Only increase number of NON-EMPTY keys tested
			tested_keys++;
		}
	}

	// If for terminated, no more memory for keys records has been found
	#ifdef __VERBOSE
	trace_printf("MESSAGE: (kms - 11.4) No empty records found in kms_search_empty_record.\n");
	#endif
	return 0;  // empty record not found
}

/*
 * Function kms_keys_num_update
 * ----------------------------
 * Function to update the value of keys_num global variable at each add/remove key
 * operation, and write the corresponding result in the Flash memory to always keep
 * the non-volatile register up-to-date.
 * It returns: 0 -> in case of success
 *            -1 -> ERROR: Hard fault
 */
int kms_keys_num_update(kms_keys_num_update_mode_t update_mode){
	int ret;

	switch(update_mode){
		case KMS_KEYS_NUM_UPDATE_INCR:
			if (keys_num == UINT32_MAX){
				#ifdef __VERBOSE
				trace_printf("ERROR: (kms - 12.1) Error @ \"keys_num == UINT32_MAX\" in kms_keys_num_update.\n");
				#endif
				return -1;  // error
			}
			keys_num++;
			break;
		case KMS_KEYS_NUM_UPDATE_DECR:
			if (keys_num == 0){
				#ifdef __VERBOSE
				trace_printf("ERROR: (kms - 12.2) Error @ \"keys_num == 0\" in kms_keys_num_update.\n");
				#endif
				return -1;  // error
			}
			keys_num--;
			break;
	}
	// Update value stored in non-volatile memory
	ret = write_nvm(KMS_KEYS_NUM_REG_BASE, &keys_num, sizeof(uint32_t));
	if (ret){
		// return error and abort
		#ifdef __VERBOSE
		trace_printf("ERROR: (kms - 12.3) Error @ write_nvm in kms_keys_num_update.\n");
		#endif
		return -1;  // error
	}
	return 0;  // success
}

/*
 * Function generate_key
 * ---------------------
 * Generate a key of key_size bytes with an hashing procedure of the seed provided by
 * the seed input argument, of size seed_size bytes; the key generated in such way is
 * encrypted with AES-256 algorithm and returned by means of the gen_key argument.
 * The keys for the HMAC-SHA256 hashing algorithm and the encryption algorithm are
 * hardcoded in the KMS library for the sake of simplicity, and considered to be
 * secret and not accessible in any way.
 * It returns: 0 -> in case of success
 *            -2 -> too large key size
 */
int generate_key(uint8_t* seed, uint16_t seed_size, uint8_t* gen_key, uint16_t key_size) {
	uint8_t key_plain[MAX_KEY_SIZE];
	int     sub_seeds_n;
	int     sub_seeds_size;
	int     ret;

	// Stop already if desired key size is > MAX_KEY_SIZE
	if (key_size > MAX_KEY_SIZE) {
		// Desired key size in bytes too big for KMS database
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 13.1) Error @ \"key_size > MAX_KEY_SIZE\" in generate_key (too large desired key of %d bytes).\n", key_size);
		#endif
		return -2;
	}

	// Generate the actual key (of key_size bytes) by hashing the seed
	/*
	 * Generated key can be max MAX_KEY_SIZE = 128 bytes, while hash generates only
	 * 32-byte fixed output: the seed is divided into as many part as needed by
	 * key_size so that each part is hashed generating a 32-byte output, then all
	 * hashes are concatenated to create a key of key_size bytes. Note that the full
	 * concatenation of hashes forming the key will always be, with the following
	 * code, a multiple of 32 bytes even if key_size is not; even if not handled for
	 * the sake of simplicity, this does not represent a problem because the SIZE
	 * field of kms_key tells anyway the correct size wich must be used.
	 */
	sub_seeds_n = CEIL_DIV(key_size, HASH_OUTPUT_LEN);
	sub_seeds_size = CEIL_DIV(seed_size, sub_seeds_n);

	if (seed_size < sub_seeds_n) {
		// Seed size in bytes too small for given desired key size
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 13.2) Error @ \"seed_size < sub_seeds_n\" in generate_key (too short seed).\n");
		#endif
		return -2;
	}

	for (int i = 0; i < sub_seeds_n; i++){
		if ( (i+1)*sub_seeds_size - 1 >= seed_size ){
			// Handle seeds with size not multiple of sub_seeds_size (only last iteration of the for may enter here)
			hmac_sha256(seed + i*sub_seeds_size, seed_size - i*sub_seeds_size, (uint8_t*)HMAC_KMS_KEY, HMAC_KMS_KEY_LEN, key_plain + i*HASH_OUTPUT_LEN);
			break;
		}
		hmac_sha256(seed + i*sub_seeds_size, sub_seeds_size, (uint8_t*)HMAC_KMS_KEY, HMAC_KMS_KEY_LEN, key_plain + i*HASH_OUTPUT_LEN);
	}

	// Encrypt the generated key before storing
	/*
	 * Encrypts and saves in the structure to store in memory the key of key_size:
	 * if key_size is not a multiple of AES_BLOCK_SIZE (16 byte for the AES-256),
	 * padding is used and thus the size of the array containing the encrypted key
	 * will be equal to the nearest greater integer wrt key_size multiple of
	 * AES_BLOCK_SIZE; however, it should never be greater than MAX_KEY_SIZE.
	 * This must be taken into account when retrieving and decryipting the key.
	 */
	ret = encrypt_cbc((char*)key_plain, key_size, (char*)AES_KMS_KEY, (char*)gen_key);
	if (ret > MAX_KEY_SIZE){
		// Encrypted key size is too big to be stored in key record structure kms_key
		#ifdef __VERBOSE
		trace_printf("WARNING: (kms - 13.3) Error @ \"encrypt_cbc > MAX_KEY_SIZE\" in generate_key (too large encrypted key of %d bytes).\n", ret);
		#endif
		return -2;
	}

	return 0;
}

/* ------------------------------------------------------------------------------- */
/* ----------------------- Key state management functions ------------------------ */
/* ------------------------------------------------------------------------------- */

/*
* Function key_state_transition_check
* -----------------------------------
* Checks if a transition is permitted or not. 
* This is compliant to the key states transition diagram in 
* SECube software documentation, chapter 8.
* In input there are the start state and the destination state.
* It returns: 1 -> in case of success
*             0 -> WARNING: transition NOT permitted
*            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
*/
int key_state_transition_check(key_state_t start_state, key_state_t end_state)
{
	int permitted = -2;
	switch (start_state)
	{
		case KMS_KEY_PREACTIVE:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 1;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 1;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 0;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 0;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 1;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break;
		case KMS_KEY_ACTIVE:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 1;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 1;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 1;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 1;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break;
		case KMS_KEY_COMPROMISED:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 0;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 0;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 0;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 1;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break;
		case KMS_KEY_SUSPENDED:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 1;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 1;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 0;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 1;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 1;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break; 
		case KMS_KEY_DEACTIVATED:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 1;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 0;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 0;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 1;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break;
		case KMS_KEY_DESTROYED:
			switch (end_state)
			{
				case KMS_KEY_PREACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_ACTIVE:
					permitted = 0;
					break;
				case KMS_KEY_COMPROMISED:
					permitted = 0;
					break;
				case KMS_KEY_SUSPENDED:
					permitted = 0;
					break; 
				case KMS_KEY_DEACTIVATED:
					permitted = 0;
					break;
				case KMS_KEY_DESTROYED:
					permitted = 0;
					break;
				
				default:
					permitted = -2;
					break;
			}
			break;
		
		default:
			permitted = -2;
			break;
	}

	return permitted;
}

/*
* Function key_state_transition
* ---------------------
* It changes the state of the key from it's state
* to the target state. Before changing it, it checks if 
* the transition is permitted.
* It returns: 1 -> in case of success
*             0 -> WARNING: transition NOT permitted
*            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
*            -3 -> WARNING: Glitch has occurred in a ret value
*/
int key_state_transition(struct kms_key* key, key_state_t end_state)
{
	int permitted = -2;

	permitted = key_state_transition_check(key->state,end_state);

	if(permitted == -2){
		#ifdef __VERBOSE
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		trace_printf("WARNING: (kms - 14.1) Error @ key_state_transition_check in key_state_transition\n");
		#endif
		return -2;
	}
	else if(permitted == 0){
		#ifdef __VERBOSE
		// WARNING: transition NOT permitted
		trace_printf("WARNING: (kms - 14.2) Error @ key_state_transition_check in key_state_transition\n");
		#endif
		return 0;
	}
	else if(permitted != 1){
		#ifdef __VERBOSE
		// External Glitching attempt affecting the return code
		trace_printf("WARNING: (kms - 14.3) Error @ key_state_transition_check in key_state_transition\n");
		#endif
		return -3;
	}

	// If here, transition is permitted
	key->state = end_state;

	return 1;
}

/*
* Function can_encrypt
* ---------------------
* Checks if the operation of encryption is permitted 
* based on the actual state of the key. 
* It returns: 1 -> in case of success
*             0 -> WARNING: operation NOT permitted in the given state
*            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
*/
int can_encrypt(key_state_t state)
{
	int permitted = -2;
	switch (state)
	{
		case KMS_KEY_PREACTIVE:
			permitted = 0;
			break;
		case KMS_KEY_ACTIVE:
			permitted = 1;
			break;
		case KMS_KEY_COMPROMISED:
			permitted = 0;
			break;
		case KMS_KEY_SUSPENDED:
			permitted = 0;
			break; 
		case KMS_KEY_DEACTIVATED:
			permitted = 0;
			break;
		case KMS_KEY_DESTROYED:
			permitted = 0;
			break;
		
		default:
			permitted = -2;
			break;
	}

	return permitted;
}

/*
* Function can_decrypt
* ---------------------
* Checks if the operation of decryption is permitted 
* based on the actual state of the key. 
* It returns: 1 -> in case of success
*             0 -> WARNING: operation NOT permitted in the given state
*            -2 -> WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
*/
int can_decrypt(key_state_t state)
{
	int permitted = -2;
	switch (state)
	{
		case KMS_KEY_PREACTIVE:
			permitted = 0;
			break;
		case KMS_KEY_ACTIVE:
			permitted = 1;
			break;
		case KMS_KEY_COMPROMISED:
			permitted = 1;
			break;
		case KMS_KEY_SUSPENDED:
			permitted = 1;
			break; 
		case KMS_KEY_DEACTIVATED:
			permitted = 1;
			break;
		case KMS_KEY_DESTROYED:
			permitted = 0;
			break;
		
		default:
			permitted = -2;
			break;
	}

	return permitted;
}