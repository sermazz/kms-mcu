#ifndef __kms_H
#define __kms_H

// My libraries
#include <nv_mem.h>


/*
 * KEY MANAGEMENT SYSTEM LIBRARY
 * -----------------------------
 * This library implements an interface towards a Key Management System (KMS)
 * based on a Non-volatile memory, in turn implemented in this project by means of
 * the ARM Semihosting mechanism.
 */


/************************************* DEFINES *************************************/

/* KMS characterization */
#define MAX_KEY_SIZE      128               /* Max 1024-bit keys */
#define MAX_KEYS_NUM      KMS_DB_LIMIT/sizeof(struct kms_key)   /* Max possible num of keys in KMS Flash mem database */

/* Translation from KMS database index i to actual non-volatile memory address */
#define KMS_DB(i)         (nvm_address_t)(KMS_DB_BASE + (kms_index_t)i * sizeof(struct kms_key))

/* Hardcoded keys for key generation by hash and keys encryption/decryption for storage */
#define HMAC_KMS_KEY      "Ji2BrexJhxxrk3wiTgiqXisb4h4GnJwV7nTBf4QMpewmNGmuiVN47hEAXxULxA5F"
#define AES_KMS_KEY       "~5W@K~3-yh*J34BtT!T&SLq;$4H;}|tf"
#define HMAC_KMS_KEY_LEN  64
#define AES_KMS_KEY_LEN   32

/* Useful fast CEIL division operation */
#define CEIL_DIV(x,y)     x/y + (x % y != 0)


/*********************************** DATA TYPES ************************************/

/* Possible states of a key in the KMS database */
/**
 * 
 * KMS_KEY_PREACTIVE:
 * The default state for every new key (The key cannot be used neither for
 * encryption nor decryption)
 * 
 * KMS_KEY_ACTIVE: 
 * The key can be used for both encryption and decryption
 * 
 * KMS_KEY_COMPROMISED:
 * The key is not secure anymore, and should be used to decrypt old encrypted files to be eventually
 * encrypted using a new key ASAP.
 * 
 * KMS_KEY_SUSPENDED:
 * The key can be used only for decryption but not for encryption (but can be activated again)
 * The time during which the key is suspended still contributes to the time that determines the
 * expiration of the key.
 * 
 * KMS_KEY_DEACTIVATED:
 * The key can be used only for decryption but not for encryption.
 * A key which is active will reach this state once it reaches its expiration time
 * 
 * KMS_KEY_DESTROYED:
 * The key has been destroyed, the encrypted (and not decrypted files) are no more accessible: the
 * key value is erased from the KMS.
 * A destroyed key is treated as an empty KMS field.
 * 
 */
// How many Bytes every enum element should require?
// Should be 4 Bytes (32-bit wide ARM arch) See --> https://stackoverflow.com/a/366026
typedef enum {
	KMS_KEY_EMPTY = 0,       /* The record of the KMS database is empty, no actual key stored */

    KMS_KEY_PREACTIVE = 1,
    KMS_KEY_ACTIVE = 2,
    KMS_KEY_COMPROMISED = 4,
    KMS_KEY_SUSPENDED = 8,
    KMS_KEY_DEACTIVATED = 16,
    KMS_KEY_DESTROYED = 32
} key_state_t;

/*
 * Note that the key itself is included in the structure along with its header so
 * that the non-volatile memory storing the KMS database with all the keys and their
 * metadata can be scanned in a simple way, like an actual database with fixed
 * records. With this structure a key can have a max size of MAX_KEY_SIZE bytes, with
 * its actual length being specified by the SIZE field.
 * This way does not aim to optimize memory usage; however, implementation is simpler
 * since allowing a variable key size, with the array containing the key out of the
 * struct kms_key and with the key fetched from NV memory basing on SIZE field, would
 * have introduced several other problems (such as finding holes for a new key after
 * old keys are removed, fragmentation problems, search problems because the stride
 * of each entry is different, ...)
 */

/* Key header + key structure for KMS in Flash memory */
/* || 4 byte ID | 2 byte SIZE | 2 byte STATE | N byte encrypted Key || */

struct kms_key {
	uint32_t id;                     /* 4 bytes   - key ID */
	uint16_t size;                   /* 2 bytes   - key size in bytes */
	key_state_t state;               /* 2 bytes   - key state */
	uint32_t cryptoperiod;           /* 4 bytes   - key cryptoperiod */
	uint32_t expire_time;            /* 4 bytes   - key expire time */
	uint8_t  key[MAX_KEY_SIZE];      /* 128 bytes - encrypted key */
};

/* Type of update of KMS keys number in database */
typedef enum {
	KMS_KEYS_NUM_UPDATE_INCR,        /* Increment keys number global variable */
	KMS_KEYS_NUM_UPDATE_DECR         /* Decrement keys number global variable */
} kms_keys_num_update_mode_t;

/*
 * The functions within this library need to communicate among each other information
 * about the position of keys inside the Flash memory region dedicated to the KMS; to
 * do so, a custom kms_index_t is used. A variable of type kms_index_t contains the
 * index of the record of the KMS database (stored in the Flash memory) containing
 * the referred key structure.
 * An index of type kms_index_t can be translated to an actual NV memory address,
 * which can be used to actually read/write the memory, with the help of the macro
 * defined above KMS_DB(i), which takes into account the memory map of the KMS region
 */
typedef uint32_t kms_index_t;        /* KMS index type, it refers to a databse record index in the KMS */

/****************************** FUNCTIONS PROTOTYPES *******************************/

/* KMS main functionalities */
int kms_init(nvm_init_t nvm_init);
int kms_add_key(uint32_t key_id, uint16_t key_size, uint8_t* seed, uint16_t seed_size, uint32_t cryptoperiod);
int kms_remove_key(uint32_t key_id);
int kms_update_key(uint32_t key_id, uint8_t* seed, uint16_t seed_size, uint32_t cryptoperiod);
int kms_get_key(uint32_t key_id, struct kms_key* key);
int kms_list_key(uint32_t* valid_keys_id);
int kms_change_status_key(uint32_t key_id, key_state_t end_state);
int kms_add_plain_key(uint32_t key_id, uint16_t key_size, uint8_t* key, uint32_t cryptoperiod);

/* Accessory functions */
int kms_search_key(uint32_t key_id, kms_index_t* key_index_p);
int kms_check_expire_time(struct kms_key* key);
int kms_search_empty_record(kms_index_t* key_index_p);
int kms_keys_num_update(kms_keys_num_update_mode_t update_mode);
int generate_key(uint8_t* seed, uint16_t seed_size, uint8_t* gen_key, uint16_t key_size);

/* Key State Management Functions */
int key_state_transition_check(key_state_t start_state, key_state_t end_state);
int key_state_transition(struct kms_key* key, key_state_t end_state);
int can_encrypt(key_state_t state);
int can_decrypt(key_state_t state);

#endif /* __kms_H */
