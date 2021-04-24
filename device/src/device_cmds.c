#include <stdio.h>
#include <string.h>
#include <stdint.h>
// For trace_printf
#include "diag/Trace.h"
// My libraries
#include <device_cmds.h>
#include <com_channel.h>
#include <kms.h>
#include <eke_exp.h>
// Computational functions libraries
#include <aes256.h>
#include <hmac_sha256.h>


/*
 * DEVICE COMMANDS
 * ---------------
 * Implementation of the library defined in device_cmds.h (see comments in
 * device_cmds.h for further details)
 */


/************************************* DEFINES *************************************/

#define __VERBOSE  /* Enable verbose trace_printf information about cmd exchange */


/********************************* EXTERN VARIABLES ********************************/

/* From com_channel.c */
extern uint8_t payload_buf_in[PAYLOAD_BUF_IN_SIZE];	   /* Buffer for input command payload */
extern uint8_t payload_buf_out[PAYLOAD_BUF_OUT_SIZE];  /* Buffer for output response payload */
const struct out_header no_output;      		       /* Empty output for channel_out */

/****************************** UTILITY FUNCTIONS **********************************/

int send_response(struct out_header header_buf_out) {
	int ret;
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* ------------------------------------------------------------------------------- */
/* --------------------- Commands functions implementation ----------------------- */
/* ------------------------------------------------------------------------------- */

/*
 * All commands are divided into three main steps:
 *
 * 1. Input elaboration: the device reads the input payload attached to the received
 *    command, stored in the internal buffer payload_buf_in, and performs some action
 *    with it, also basing on the input flags options, if any;
 * 2. Output definition: with the results from the input payload elaboration, the
 *    internal buffer for output payload payload_buf_out is filled, along with its
 *    corresponding output header;
 * 3. Send response: the output header+payload temporarily stored in internal buffers
 *    are sent to the host by writing them to the output channel.
 *
 * Beware that, apart from their input arguments, the buffer for the input payload
 * (stored as a global variable in com_channel.c), payload_buf_out, should be
 * considered as an input of the commands functions; in the same way, payload_buf_out
 * is written as an output.
 *
 * At the beginning of each command function execution, an header_buf_out structure
 * is declared and initialized to no_output, so that even if not all the fields are
 * assigned some value, the structure written to output channel is still meaningful
 * (this is needed for scalability reasons, since in the future other fields may be
 * added, which were not assigned in old command functions: in this way input header
 * can be modified without modifying definition of old command functions)
 *
 * All commands functions return:
 * 		>0 = if response successfully sent; the value corresponds to out payload size
 * 		 0 = empty output payload
 * 		-1 = an error occurred during input elaboration or while sending the cmd
 * 			 response to the host
 */

/*
 * Function cmd_test_ping
 * ----------------------
 * Test command which does not need an input payload, and only gives a feedback
 * about the reception of the command itself, writing a static response to the output
 * channel.
 */
int cmd_test_ping(){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_test_ping.\n");
	#endif
	// No input payload to be used

	/********** Output definition **********/
	// Define output payload
	sprintf((char*)payload_buf_out, "Pong");
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf

	return send_response(header_buf_out);
}

/*
 * Function cmd_test_payload
 * -------------------------
 * Example of a command using the received payload: it gives a feedback about the
 * reception of the command and prints the received payload on the console. Also,
 * it writes a static response to the output channel.
 */
int cmd_test_payload (uint16_t payload_in_len){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_test_payload.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif

	/********** Output definition **********/
	if(!strcmp((char*)payload_buf_in, "Test dummy input payload")){
		// Define output payload
		sprintf((char*)payload_buf_out, "Test dummy output payload");
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in payload test: input payload not received correctly.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}

	return send_response(header_buf_out);
}


/*
 * Function cmd_encrypt
 * --------------------
 * Encrypts the received payload according to the AES-256 encryption algorithm in ECB
 * or CBC operating mode, basing on received flags, and sends the obtained cipher
 * text back to the requestor. The plain text is encrypted with the key in the KMS
 * database given by the input argument key_id.
 */
int cmd_encrypt(uint16_t payload_in_len, uint32_t key_id, uint16_t flags){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	struct kms_key extracted_key;
	int ret;

	aes_mode_t aes_mode;
	uint16_t payload_out_len;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_encrypt.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif
	// Flags decoding
	aes_mode = 0x0001 & flags;

	// Key extraction
	ret = kms_get_key(key_id, &extracted_key);
	if (ret > 0 && extracted_key.size == AES_KEYLEN) {
		// Key found (and of the correct size)
		// Let's check if it is also enabled for encryption
		ret = can_encrypt(extracted_key.state);
		if (ret == -2) {
			// ILLEGAL state/the check function has glitched, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "ILLEGAL key state, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret == 0) {
			// This key cannot be used for encryption (its state does not permit it)
			// Define output payload
			sprintf((char*)payload_buf_out, "This key cannot be used for encryption");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret != 1) {
			// External Glitching attempt affecting the return code, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "External glitching attempt, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}

		// If here, the key is allowed to be used for encryption
		switch(aes_mode) {
			case AES_ECB_MODE:
				//payload_out_len = encrypt_ecb((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				payload_out_len = encrypt_ecb((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				break;
			case AES_CBC_MODE:
				//payload_out_len = encrypt_cbc((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				payload_out_len = encrypt_cbc((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				break;
			default:
				// should never be reached
				sprintf((char*)payload_buf_out, "Error: undefined AES mode of operation");
				// Define output header
				header_buf_out.err_code = OUT_ERR_ERROR;
				header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
				return send_response(header_buf_out);
				break;
		}
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = payload_out_len;
	} else if (ret > 0 && extracted_key.size != AES_KEYLEN) {
		/* Key not suitable for AES-256 cipher */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key usage: key not suitable for AES-256 cipher, its size must be 32 bytes.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		// Key not found
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		// Define output payload
		sprintf((char*)payload_buf_out, "ILLEGAL state: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu cannot be used for this purpose", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		// Define output payload
		sprintf((char*)payload_buf_out, "Glitch has occurred: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		// ERROR: an hard fault occurs
		return -1;
	}

	return send_response(header_buf_out);
}

/*
 * Function cmd_decrypt
 * --------------------
 * Decrypt the cipher text in the payload, previously encrypted with AES-256
 * encryption algorithm in ECB or CBC operating mode (specified by flags), and sends
 * the obtained plain text back to the requestor. The cipher text is decrypted with
 * the key in the KMS database given by the input argument key_id.
 */
int cmd_decrypt(uint16_t payload_in_len, uint32_t key_id, uint16_t flags){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	struct kms_key extracted_key;
	int ret;

	aes_mode_t aes_mode;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_decrypt.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (hexadecimal):\n");
	for(int i = 0; i < payload_in_len; i++)
		trace_printf("0x%02x ", (unsigned char)payload_buf_in[i]);
	trace_printf("\n");
	#endif
	// Flags decoding
	aes_mode = 0x0001 & flags;

	// Key extraction
	ret = kms_get_key(key_id, &extracted_key);
	if (ret > 0 && extracted_key.size == AES_KEYLEN) {
		// Key found
		// Let's check if it is also enabled for decryption
		ret = can_decrypt(extracted_key.state);
		if (ret == -2) {
			// ILLEGAL state/the check function has glitched, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "Glitch in the key state, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret == 0) {
			// This key cannot be used for decryption (its state does not permit it)
			// Define output payload
			sprintf((char*)payload_buf_out, "This key cannot be used for decryption");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret != 1) {
			// External Glitching attempt affecting the return code, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "External glitching attempt, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}

		// If here, the key is allowed to be used for decryption
		switch(aes_mode){
			case AES_ECB_MODE:
				//decrypt_ecb((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				decrypt_ecb((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				break;
			case AES_CBC_MODE:
				//decrypt_cbc((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				decrypt_cbc((char*)payload_buf_in, payload_in_len, (char*)extracted_key.key, (char*)payload_buf_out);
				break;
			default:
				// should never be reached
				sprintf((char*)payload_buf_out, "Error: undefined AES mode of operation");
				// Define output header
				header_buf_out.err_code = OUT_ERR_ERROR;
				header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
				return send_response(header_buf_out);
				break;
		}
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = payload_in_len;

	} else if (ret > 0 && extracted_key.size != AES_KEYLEN) {
		// Key not suitable for AES-256 cipher
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key usage: key not suitable for AES-256 cipher, its size must be 32 bytes.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		// Key not found
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		// Define output payload
		sprintf((char*)payload_buf_out, "ILLEGAL state: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu cannot be used for this purpose", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		// Define output payload
		sprintf((char*)payload_buf_out, "Glitch has occurred: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		// ERROR: an hard fault occurs
		return -1;
	}

	return send_response(header_buf_out);
}

/*
 * Function cmd_hmac_sign
 * -----------------
 * Invoke HMAC_SHA256 implementation to sign a message
 */
int cmd_hmac_sign(uint16_t payload_in_len, uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	struct kms_key extracted_key;
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_hmac_sign.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif

	// Key extraction
	ret = kms_get_key(key_id, &extracted_key);
	if (ret > 0) {
		// Key found
		// Let's check if it is also enabled for HMAC

		ret = can_encrypt(extracted_key.state);
		if (ret == -2) {
			// ILLEGAL state/the check function has glitched, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "Glitch in the key state, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret == 0) {
			// This key cannot be used for HMAC (its state does not permit it)
			// Define output payload
			sprintf((char*)payload_buf_out, "This key cannot be used for HMAC_sign");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret != 1) {
			// External Glitching attempt affecting the return code, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "External glitching attempt, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}

		// If here, the key is allowed to be used for decryption
		ret = hmac_sha256(payload_buf_in, payload_in_len, extracted_key.key, extracted_key.size, payload_buf_out);
		if (ret == 1) {
			// Error
			// Define output payload
			sprintf((char*)payload_buf_out, "Error while executing HMAC_sign");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}
		// OK
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = HASH_OUTPUT_LEN; // fixed HMAC-SHA-256 output size
	} else if (ret == 0) {
		/* Key not found */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key with ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		// Key not found
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		// Define output payload
		sprintf((char*)payload_buf_out, "ILLEGAL state: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu cannot be used for this purpose", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		// Define output payload
		sprintf((char*)payload_buf_out, "Glitch has occurred: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		// ERROR: an hard fault occurs
		return -1;
	}

	return send_response(header_buf_out);
}

/*
 * Function cmd_hmac_check
 * -----------------
 * Invoke HMAC_SHA256 implementation to check a message
 */
int cmd_hmac_check(uint16_t payload_in_len, uint32_t key_id) {
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	struct kms_key extracted_key;
	int ret;

	uint8_t digest[HASH_OUTPUT_LEN], digest_out[HASH_OUTPUT_LEN];
	uint8_t message[PAYLOAD_BUF_IN_SIZE - HASH_OUTPUT_LEN];

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_hmac_check.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif

	// Key extraction
	ret = kms_get_key(key_id, &extracted_key);
	if (ret > 0) {
		// Key found
		// Let's check if it is also enabled for HMAC
		ret = can_decrypt(extracted_key.state);
		if (ret == -2) {
			// ILLEGAL state/the check function has glitched, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "Glitch in the key state, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret == 0) {
			// This key cannot be used for HMAC (its state does not permit it)
			// Define output payload
			sprintf((char*)payload_buf_out, "This key cannot be used for HMAC_check");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		} else if (ret != 1) {
			// External Glitching attempt affecting the return code, setting it to the COMPROMISED state
			extracted_key.state = KMS_KEY_COMPROMISED;
			// Define output payload
			sprintf((char*)payload_buf_out, "External glitching attempt, key set to COMPROMISED state as precaution");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}

		// Separate the digest from the message
		memcpy(digest, payload_buf_in, HASH_OUTPUT_LEN);
		memcpy(message, &(payload_buf_in[HASH_OUTPUT_LEN]), payload_in_len - HASH_OUTPUT_LEN);

		// If here, the key is allowed to be used for decryption
		ret = hmac_sha256(message, payload_in_len - HASH_OUTPUT_LEN, extracted_key.key, extracted_key.size, digest_out);
		if (ret == 1) {
			// Error
			// Define output payload
			sprintf((char*)payload_buf_out, "Error while executing HMAC_check");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}

		// OK
		// Check if computed digest is equal to the given digest
		if (memcmp(digest, digest_out, HASH_OUTPUT_LEN)) {
			// Error, the two digest are different
			// Define output payload
			sprintf((char*)payload_buf_out, "ERROR: the computed HMAC digest does not match the digest of the given message");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
			return send_response(header_buf_out);
		}
		// OK, the two digest match
		// Define output payload
		sprintf((char*)payload_buf_out, "OK: the computed HMAC digest matches the digest of the given message");
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		/* Key not found */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key with ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		// Define output payload
		sprintf((char*)payload_buf_out, "ILLEGAL state: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key retrieval: key ID#%lu cannot be used for this purpose", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		// Define output payload
		sprintf((char*)payload_buf_out, "Glitch has occurred: setting key state to COMPROMISED as precaution (key ID#%lu)", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		// ERROR: an hard fault occurs
		return -1;
	}

	return send_response(header_buf_out);
}

/*
 * Function cmd_add_key
 * --------------------
 * Generate a new key of key_size bytes by hashing the seed in payload_buf_in, whose
 * size is given by payload_in_len; then, add the key with an id given by key_id to
 * the KMS database; the outcome of the procedure is printed on the output payload.
 */
int cmd_add_key(uint16_t payload_in_len, uint32_t key_id, uint16_t key_size, uint32_t key_cryptoperiod){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_add_key.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif

	// Generate and add key in KMS database
	ret = kms_add_key(key_id, key_size, payload_buf_in, payload_in_len, key_cryptoperiod);
	if (ret > 0) {
		/* Key successfully addedd */
		// Define output payload
		sprintf((char*)payload_buf_out, "New key with ID#%lu successfully generated and added to KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		/* No space left to add a new key */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key creation: no space left in Flash memory.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		/* Error in key generation */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key generation: too small %u-byte seed for %u-byte key size or too large key for KMS database entry.", payload_in_len, key_size);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		/* Already existing key with key_id */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key creation: key with ID#%lu already existing.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else {
		return -1;  // return error and abort
	}
	
	return send_response(header_buf_out);
}

/*
 * Function cmd_remove_key
 * -----------------------
 * Look for the key of id key_id in the KMS database and completely delete it; the
 * outcome of the procedure is printed on the output payload.
 */
int cmd_remove_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_remove_key.\n");
	// No input payload to be used
	#endif

	// Generate and add key in KMS database
	ret = kms_remove_key(key_id);
	if (ret > 0) {
		/* Key successfully removed */
		// Define output payload
		sprintf((char*)payload_buf_out, "Key with ID#%lu successfully removed from KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		/* Key id not found */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key deletion: key with ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else
		return -1;  // return error and abort

	return send_response(header_buf_out);
}

/*
 * Function cmd_update_key
 * -----------------------
 * Reseed an existing key in the KMS database keeping its old key size; the key to be
 * updated is chosen by means of the key_id input; the outcome of the procedure is
 * printed on the output payload.
 */
int cmd_update_key(uint16_t payload_in_len, uint32_t key_id, uint32_t key_cryptoperiod){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_update_key.\n");
	// Print on console the received input payload
	trace_printf("Received cmd payload (string): \"%.*s\"\n", payload_in_len, payload_buf_in);
	#endif

	// Generate and add key in KMS database
	ret = kms_update_key(key_id, payload_buf_in, payload_in_len, key_cryptoperiod);
	if (ret > 0) {
		/* Key successfully addedd */
		// Define output payload
		sprintf((char*)payload_buf_out, "Existing key with ID#%lu successfully updated in the KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == 0) {
		/* Key id not found */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key update: key with ID#%lu not found in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -2) {
		/* Error in key generation */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in key generation: too small %u-byte seed for the key or too big encrypted key.", payload_in_len);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else
			return -1;  // return error and abort

	return send_response(header_buf_out);
}

/*
 * Function cmd_list_keys
 * ----------------------
 * Send to the output payload a list of the VALID keys ID available in the KMS
 * database of the device.
 */
int cmd_list_keys(){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	uint32_t valid_keys_id[MAX_KEYS_NUM];
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_list_keys.\n");
	// No input payload to be used
	#endif

	// Generate and add key in KMS database
	ret = kms_list_key(valid_keys_id);

	/********** Output definition **********/
	if (ret > 0) {
		/* All keys id successfully retrieved */
		// Define output payload
		for (int i = 0; i < ret; i++)
			// Copy in output payload buffer as array of 4-byte words
			memcpy(payload_buf_out + 4*i, valid_keys_id + i, sizeof(uint32_t));
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = sizeof(uint32_t) * ret;
	} else if (ret == 0) {
		/* No keys in the KMS database */
		// Define output payload
		sprintf((char*)payload_buf_out, "KMS database is empty.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else
		return -1;  // return error and abort

	return send_response(header_buf_out);
}


// ----- Key Status Commands ----- //

/*
 * Function cmd_activate_key
 * -----------------------
 * This function looks for the key of id key_id in the KMS database and 
 * change the status to ACTIVE, if possible.
 */
int cmd_activate_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_active_key.\n");
	// No input payload to be used
	#endif

	ret = kms_change_status_key(key_id, KMS_KEY_ACTIVE);
	if (ret == 0) {
		// WARNING: key not found in KMS database
		sprintf((char*)payload_buf_out, "WARNING: Key not found in KMS DB");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -1) {
		// ERROR: an hard fault occurs

		// sprintf((char*)payload_buf_out, "ERROR: An Hard Fault has occurred");
		// // Define output header
		// header_buf_out.err_code = OUT_ERR_ERROR;
		// header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		// return send_response(header_buf_out);

		return -1;
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		sprintf((char*)payload_buf_out, "WARNING: The source/destination state is not in the graph");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		sprintf((char*)payload_buf_out, "WARNING: This transition is not allowed for this key");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		sprintf((char*)payload_buf_out, "WARNING: The KMS has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -5) {
		// WARNING: transition is a loop
		sprintf((char*)payload_buf_out, "WARNING: The requested transition is a loop");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret != 1) {
		// External Glitching attempt affecting the return code
		sprintf((char*)payload_buf_out, "WARNING: The device has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	}

	sprintf((char*)payload_buf_out, "OK: Key #%lu Activated", key_id);
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	return send_response(header_buf_out);
}

/*
 * Function cmd_suspend_key
 * -----------------------
 * This function looks for the key of id key_id in the KMS database and 
 * change the status to SUSPENDED, if possible
 */
int cmd_suspend_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_suspend_key.\n");
	// No input payload to be used
	#endif

	ret = kms_change_status_key(key_id, KMS_KEY_SUSPENDED);
	if (ret == 0) {
		// WARNING: key not found in KMS database
		sprintf((char*)payload_buf_out, "WARNING: Key not found in KMS DB");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -1) {
		// ERROR: an hard fault occurs

		// sprintf((char*)payload_buf_out, "ERROR: An Hard Fault has occurred");
		// // Define output header
		// header_buf_out.err_code = OUT_ERR_ERROR;
		// header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		// return send_response(header_buf_out);

		return -1;
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		sprintf((char*)payload_buf_out, "WARNING: The source/destination state is not in the graph");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		sprintf((char*)payload_buf_out, "WARNING: This transition is not allowed for this key");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		sprintf((char*)payload_buf_out, "WARNING: The KMS has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -5) {
		// WARNING: transition is a loop
		sprintf((char*)payload_buf_out, "WARNING: The requested transition is a loop");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret != 1) {
		// External Glitching attempt affecting the return code
		sprintf((char*)payload_buf_out, "WARNING: The device has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	}

	sprintf((char*)payload_buf_out, "OK: Key #%lu Suspended", key_id);
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	return send_response(header_buf_out);
}

/*
 * Function cmd_deactive_key
 * -----------------------
 * This function looks for the key of id key_id in the KMS database and 
 * change the status to DEACTIVE, if possible.
 */
int cmd_deactivate_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_deactivate_key.\n");
	// No input payload to be used
	#endif

	ret = kms_change_status_key(key_id, KMS_KEY_DEACTIVATED);
	if (ret == 0) {
		// WARNING: key not found in KMS database
		sprintf((char*)payload_buf_out, "WARNING: Key not found in KMS DB");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -1) {
		// ERROR: an hard fault occurs

		// sprintf((char*)payload_buf_out, "ERROR: An Hard Fault has occurred");
		// // Define output header
		// header_buf_out.err_code = OUT_ERR_ERROR;
		// header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		// return send_response(header_buf_out);

		return -1;
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		sprintf((char*)payload_buf_out, "WARNING: The source/destination state is not in the graph");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		sprintf((char*)payload_buf_out, "WARNING: This transition is not allowed for this key");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		sprintf((char*)payload_buf_out, "WARNING: The KMS has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -5) {
		// WARNING: transition is a loop
		sprintf((char*)payload_buf_out, "WARNING: The requested transition is a loop");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret != 1) {
		// External Glitching attempt affecting the return code
		sprintf((char*)payload_buf_out, "WARNING: The device has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	}

	sprintf((char*)payload_buf_out, "OK: Key #%lu Deactivated", key_id);
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	return send_response(header_buf_out);
}

/*
 * Function cmd_compromise_key
 * -----------------------
 * This function looks for the key of id key_id in the KMS database and 
 * change the status to COMPROMISED, if possible
 */
int cmd_compromise_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_compromise_key.\n");
	// No input payload to be used
	#endif

	ret = kms_change_status_key(key_id, KMS_KEY_COMPROMISED);

	if (ret == 0) {
		// WARNING: key not found in KMS database
		sprintf((char*)payload_buf_out, "WARNING: Key not found in KMS DB");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -1) {
		// ERROR: an hard fault occurs

		// sprintf((char*)payload_buf_out, "ERROR: An Hard Fault has occurred");
		// // Define output header
		// header_buf_out.err_code = OUT_ERR_ERROR;
		// header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		// return send_response(header_buf_out);

		return -1;
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		sprintf((char*)payload_buf_out, "WARNING: The source/destination state is not in the graph");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		sprintf((char*)payload_buf_out, "WARNING: This transition is not allowed for this key");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		sprintf((char*)payload_buf_out, "WARNING: The KMS has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -5) {
		// WARNING: transition is a loop
		sprintf((char*)payload_buf_out, "WARNING: The requested transition is a loop");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret != 1) {
		// External Glitching attempt affecting the return code
		sprintf((char*)payload_buf_out, "WARNING: The device has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	}

	sprintf((char*)payload_buf_out, "OK: Key #%lu Compromised", key_id);
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	return send_response(header_buf_out);
}

/*
 * Function cmd_destroy_key
 * -----------------------
 * This function looks for the key of id key_id in the KMS database and 
 * change the status to DESTROYED, if possible
 */
int cmd_destroy_key(uint32_t key_id){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_destroy_key.\n");
	// No input payload to be used
	#endif

	ret = kms_change_status_key(key_id, KMS_KEY_DESTROYED);

	if (ret == 0) {
		// WARNING: key not found in KMS database
		sprintf((char*)payload_buf_out, "WARNING: Key not found in KMS DB");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -1) {
		// ERROR: an hard fault occurs

		// sprintf((char*)payload_buf_out, "ERROR: An Hard Fault has occurred");
		// // Define output header
		// header_buf_out.err_code = OUT_ERR_ERROR;
		// header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		// return send_response(header_buf_out);

		return -1;
	} else if (ret == -2) {
		// WARNING: ILLEGAL start_state/end_state (i.e. not in the state graph)
		sprintf((char*)payload_buf_out, "WARNING: The source/destination state is not in the graph");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -3) {
		// WARNING: transition NOT permitted
		sprintf((char*)payload_buf_out, "WARNING: This transition is not allowed for this key");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -4) {
		// WARNING: glitch has occurred in a ret value
		sprintf((char*)payload_buf_out, "WARNING: The KMS has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret == -5) {
		// WARNING: transition is a loop
		sprintf((char*)payload_buf_out, "WARNING: The requested transition is a loop");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	} else if (ret != 1) {
		// External Glitching attempt affecting the return code
		sprintf((char*)payload_buf_out, "WARNING: The device has glitched");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		return send_response(header_buf_out);
	}

	sprintf((char*)payload_buf_out, "OK: Key #%lu Destroyed", key_id);
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	return send_response(header_buf_out);
}


/*
 * Function cmd_kap_1a
 * -------------------
 * Step #1 of the KAP protocol for Encrypted Key Exchange; the device A generates
 * new beta and alpha uint32_t parameters and a local random number, to compute the
 * exponentiation which is then sent encrypted to device B, together with beta and
 * alpha in plain text. The output payload should always have a length of 24 bytes
 * and it is arranged in the following way:
 * | beta (4 bytes) | alpha (4 bytes) | encrypted exponentiation (16 bytes) |
 */
int cmd_kap_1a(){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;
	uint32_t beta, alpha;
	uint8_t enc_pow_a[AES_BLOCK_SIZE];

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_kap_1a.\n");
	#endif

	// Execute command
	ret = eke_kap_step1_a(&beta, &alpha, enc_pow_a);
	/* ret should always be AES_BLOCK_SIZE because it is the length of an uint32_t (i.e. 4 bytes) encrypted with
	 * AES-256, which should pad it until the next multiple of AES_BLOCK_SIZE bytes is reached, i.e. 16 bytes
	 */

	/********** Output definition **********/
	if (ret == AES_BLOCK_SIZE) {
		/* All parameters generated correctly */
		// Define output payload (custom structure for this cmd)
		memcpy((void*)payload_buf_out, (void*)(&beta), sizeof(uint32_t));                        // 4 bytes  - beta
		memcpy((void*)(payload_buf_out + sizeof(uint32_t)), (void*)(&alpha), sizeof(uint32_t));  // 4 bytes  - alpha
		memcpy((void*)(payload_buf_out + 2*sizeof(uint32_t)), (void*)enc_pow_a, AES_BLOCK_SIZE); // 16 bytes - encrypted local_pow

		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = 2*sizeof(uint32_t) + AES_BLOCK_SIZE;
	} else if (ret == 0) {
		/* Error in beta and alpha generation */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in alpha parameter generation: no primitive roots found for beta, please try again.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else
		return -1;  // return error and abort

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_2b
 * -------------------
 * Step #2 of the KAP protocol for Encrypted Key Exchange: device B receives the
 * beta and alpha parameters in plain text generated by device A and the encrypted
 * result of device A exponentiation. It decrypts the remote exponentiation and
 * computes the shared exponentiation, deriving the shared key K, then it generates
 * a random challenge and encrypts it with K, sending it to device A along with the
 * encrypted result of device B local exponentiation.
 * This function reads an input payload with the following structure
 * | beta (4 bytes) | alpha (4 bytes) | encrypted exponentiation A (16 bytes) |
 * and produces an output payload with the following structure
 * | encrypted exponentiation B (16 bytes) | encrypted challenge B (16 bytes) |
 */
int cmd_kap_2b(uint16_t payload_in_len, uint16_t key_size){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;
	uint32_t alpha, beta;
	uint8_t enc_pow_a[AES_BLOCK_SIZE];
	uint8_t enc_pow_b[AES_BLOCK_SIZE];
	uint8_t enc_chlg_b[AES_BLOCK_SIZE];

	// First, check that payload is of the expected size for decoding
	if (payload_in_len == 2*sizeof(uint32_t) + AES_BLOCK_SIZE){
		/********** Input elaboration **********/
		#ifdef __VERBOSE
		trace_printf("Received command cmd_kap_2b.\n");
		#endif

		// Decode input payload (custom structure from cmd cmd_kap_1a)
		memcpy((void*)(&beta), (void*)payload_buf_in, sizeof(uint32_t));                        // 4 bytes  - beta
		memcpy((void*)(&alpha), (void*)(payload_buf_in + sizeof(uint32_t)), sizeof(uint32_t));  // 4 bytes  - alpha
		memcpy((void*)enc_pow_a, (void*)(payload_buf_in + 2*sizeof(uint32_t)), AES_BLOCK_SIZE); // 16 bytes - encrypted remote_pow

		// Execute command
		ret = eke_kap_step2_b(beta, alpha, enc_pow_a, enc_pow_b, enc_chlg_b, key_size);
		/* ret should always be AES_BLOCK_SIZE*2 (two 4-byte data individually encrypted with AES-256, i.e. 16 bytes each */

		/********** Output definition **********/
		if (ret == AES_BLOCK_SIZE*2) {
			/* All parameters generated correctly */
			// Define output payload (custom structure for this cmd)
			memcpy((void*)payload_buf_out, (void*)enc_pow_b, AES_BLOCK_SIZE);            // 16 bytes - encrypted local_pow
			memcpy((void*)(payload_buf_out + ret/2), (void*)enc_chlg_b, AES_BLOCK_SIZE); // 16 bytes - encrypted local_challenge
			// Define output header
			header_buf_out.err_code = OUT_ERR_NOERR;
			header_buf_out.length =  AES_BLOCK_SIZE*2;
		} else if (ret > 0 && ret != AES_BLOCK_SIZE*2) {
			/* Unexpected output size */
			// Define output payload
			sprintf((char*)payload_buf_out, "Unexpected output size from step #2 procedure of EKE Key Agreement Protocol; produced %d bytes instead of %d.", ret, AES_BLOCK_SIZE*2);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else if (ret == -2) {
			/* Too big desired key size */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in shared key generation: too big desired size of %hu bytes for key size, maximum is %d.", key_size, HASH_OUTPUT_LEN);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else
			return -1;  // return error and abort
	} else {
		/* Unexpected input payload length */
		// Define output payload
		sprintf((char*)payload_buf_out, "Unexpected input payload size; received %hu bytes instead of %d.", payload_in_len, 2*sizeof(uint32_t) + AES_BLOCK_SIZE);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_3a
 * -------------------
 * Step #3 of the KAP protocol for Encrypted Key Exchange: device A computes the
 * shared exponentiation, generates the shared key, solves the challenge from B and
 * creates a random challenge for B to validate the key.
 * This function reads an input payload with the following structure
 * | encrypted exponentiation B (16 bytes) | encrypted challenge B (16 bytes) |
 * and produces an output payload with the following structure
 * | encrypted {reply to challenge from B, challenge A} (16 bytes) |
 */
int cmd_kap_3a(uint16_t payload_in_len, uint16_t key_size){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;
	uint8_t enc_pow_b[AES_BLOCK_SIZE];
	uint8_t enc_chlg_b[AES_BLOCK_SIZE];
	uint8_t enc_reply_a[AES_BLOCK_SIZE];

	// First, check that payload is of the expected size for decoding
	if (payload_in_len == AES_BLOCK_SIZE*2){
		/********** Input elaboration **********/
		#ifdef __VERBOSE
		trace_printf("Received command cmd_kap_3a.\n");
		#endif

		// Decode input payload (custom structure from cmd cmd_kap_2b)
		memcpy((void*)enc_pow_b, (void*)payload_buf_in, AES_BLOCK_SIZE);                     // 16 bytes - encrypted remote_pow
		memcpy((void*)enc_chlg_b, (void*)(payload_buf_in + AES_BLOCK_SIZE), AES_BLOCK_SIZE); // 16 bytes - encrypted remote_challenge

		// Execute command
		ret = eke_kap_step3_a(enc_pow_b, enc_chlg_b, enc_reply_a, key_size);
		/* ret should always be AES_BLOCK_SIZE (two 4-byte data concatenated encrypted with AES-256, i.e. 16 bytes in total) */

		/********** Output definition **********/
		if (ret == AES_BLOCK_SIZE) {
			/* Reply generated correctly */
			// Define output payload (custom structure for this cmd)
			memcpy((void*)payload_buf_out, (void*)enc_reply_a, AES_BLOCK_SIZE); // 16 bytes - encrypted {local_challenge, challenge B reply}
			// Define output header
			header_buf_out.err_code = OUT_ERR_NOERR;
			header_buf_out.length =  AES_BLOCK_SIZE;
		} else if (ret > 0 && ret != AES_BLOCK_SIZE) {
			/* Unexpected output size */
			// Define output payload
			sprintf((char*)payload_buf_out, "Unexpected output size from step #3 procedure of EKE Key Agreement Protocol; produced %d bytes instead of %d.", ret, AES_BLOCK_SIZE);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else if (ret == -2) {
			/* Too big desired key size */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in shared key generation: too big desired size of %hu bytes for key size, maximum is %d.", key_size, HASH_OUTPUT_LEN);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else
			return -1;  // return error and abort
	} else {
		/* Unexpected input payload length */
		// Define output payload
		sprintf((char*)payload_buf_out, "Unexpected input payload size; received %hu bytes instead of %d.", payload_in_len, 2*AES_BLOCK_SIZE);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_4b
 * -------------------
 * Step #4 of the KAP protocol for Encrypted Key Exchange: device B verify the
 * solution to its challenge received from A and compute the reply to the challenge
 * received from B.
 * This function reads an input payload with the following structure
 * | encrypted {reply to challenge from B, challenge A} (16 bytes) |
 * and produces an output payload with the following structure
 * | encrypted reply to challenge from A (16 bytes) |
 */
int cmd_kap_4b(uint16_t payload_in_len){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;
	uint8_t enc_reply_a[AES_BLOCK_SIZE];
	uint8_t enc_reply_b[AES_BLOCK_SIZE];

	// First, check that payload is of the expected size for decoding
	if (payload_in_len == AES_BLOCK_SIZE){
		/********** Input elaboration **********/
		#ifdef __VERBOSE
		trace_printf("Received command cmd_kap_4b.\n");
		#endif

		// Decode input payload (custom structure from cmd cmd_kap_3a)
		memcpy((void*)enc_reply_a, (void*)payload_buf_in, AES_BLOCK_SIZE); // 16 bytes - encrypted {challenge_reply_a, remote_challenge}

		// Execute command
		ret = eke_kap_step4_b(enc_reply_a, enc_reply_b);
		/* ret should always be AES_BLOCK_SIZE (a 4-byte uint32_t encrypted with AES-256, i.e. 16 bytes in total) */

		/********** Output definition **********/
		if (ret == AES_BLOCK_SIZE) {
			/* Reply generated correctly */
			// Define output payload (custom structure for this cmd)
			memcpy((void*)payload_buf_out, (void*)enc_reply_b, AES_BLOCK_SIZE); // 16 bytes - encrypted challenge_reply_b
			// Define output header
			header_buf_out.err_code = OUT_ERR_NOERR;
			header_buf_out.length =  AES_BLOCK_SIZE;
		} else if (ret > 0 && ret != AES_BLOCK_SIZE) {
			/* Unexpected output size */
			// Define output payload
			sprintf((char*)payload_buf_out, "Unexpected output size from step #4 procedure of EKE Key Agreement Protocol; produced %d bytes instead of %d.", ret, AES_BLOCK_SIZE);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else if (ret == -2) {
			/* WARNING: the challenge solution received by B from A is not correct */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in KAP: the received challenge solution is not correct.");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else
			return -1;  // return error and abort
	} else {
		/* Unexpected input payload length */
		// Define output payload
		sprintf((char*)payload_buf_out, "Unexpected input payload size; received %hu bytes instead of %d.", payload_in_len, AES_BLOCK_SIZE);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_5a
 * -------------------
 * Step #5 of the KAP protocol for Encrypted Key Exchange: device A verifies the
 * solution to its challenge received from B and, if correct, stores the new shared
 * key in its KMS and returns with a positive acknowledgment.
 * This function reads an input payload with the following structure
 * | encrypted reply to challenge from A (16 bytes) |
 */
int cmd_kap_5a(uint16_t payload_in_len, uint32_t key_id, uint32_t key_cryptoperiod){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;
	uint8_t enc_reply_b[AES_BLOCK_SIZE];

	// First, check that payload is of the expected size for decoding
	if (payload_in_len == AES_BLOCK_SIZE){
		/********** Input elaboration **********/
		#ifdef __VERBOSE
		trace_printf("Received command cmd_kap_5a.\n");
		#endif

		// Decode input payload (custom structure from cmd cmd_kap_3a)
		memcpy((void*)enc_reply_b, (void*)payload_buf_in, AES_BLOCK_SIZE); // 16 bytes - encrypted challenge_reply_b

		// Execute command
		ret = eke_kap_step5_a(enc_reply_b, key_id, key_cryptoperiod);

		/********** Output definition **********/
		if (ret == 0) {
			/* Key successfully agreed */
			// Define output payload
			sprintf((char*)payload_buf_out, "Shared key successfully agreed and added to KMS database with ID#%lu.", key_id);
			// Define output header
			header_buf_out.err_code = OUT_ERR_NOERR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else if (ret == -2) {
			/* WARNING: the challenge solution received by A from B is not correct */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in KAP: the received challenge solution is not correct.");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		}else if (ret == -3) {
			/* WARNING: no space left in KMS storage to add a new key */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in KAP: no space left in Flash memory to add a new key to KMS database.");
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else if (ret == -4) {
			/* WARNING: key with given key_id already present in KMS database */
			// Define output payload
			sprintf((char*)payload_buf_out, "Error in KAP: key with ID#%lu already existing in KMS database.", key_id);
			// Define output header
			header_buf_out.err_code = OUT_ERR_ERROR;
			header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
		} else
			return -1;  // return error and abort
	} else {
		/* Unexpected input payload length */
		// Define output payload
		sprintf((char*)payload_buf_out, "Unexpected input payload size; received %hu bytes instead of %d.", payload_in_len, AES_BLOCK_SIZE);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_6b
 * -------------------
 * Step #6 of the KAP protocol for Encrypted Key Exchange: the action from the host
 * of calling this command is equivalent to a positive ack from device A to device B,
 * telling the latter that the shared key is valid and it has to store it in its KMS
 * as well. This command should only be called if step #5 in device A returned with a
 * positive acknowledgment.
 */
int cmd_kap_6b(uint32_t key_id, uint32_t key_cryptoperiod){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_kap_6b.\n");
	#endif

	// Execute command
	ret = eke_kap_step6_b(key_id, key_cryptoperiod);

	/********** Output definition **********/
	if (ret == 0) {
		/* Key successfully agreed */
		// Define output payload
		sprintf((char*)payload_buf_out, "Shared key successfully agreed and added to KMS database with ID#%lu.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_NOERR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	}else if (ret == -2) {
		/* WARNING: no space left in KMS storage to add a new key */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in KAP: no space left in Flash memory to add a new key to KMS database.");
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else if (ret == -3) {
		/* WARNING: key with given key_id already present in KMS database */
		// Define output payload
		sprintf((char*)payload_buf_out, "Error in KAP: key with ID#%lu already existing in KMS database.", key_id);
		// Define output header
		header_buf_out.err_code = OUT_ERR_ERROR;
		header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf
	} else
		return -1;  // return error and abort

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}

/*
 * Function cmd_kap_reset
 * ----------------------
 * Command to reset he KAP protocol state for security reasons; all the buffer
 * global variables of the protocol get set to zero when this command is called.
 */
int cmd_kap_reset(){
	struct out_header header_buf_out = no_output;  /* Buffer for output header, initialized for scalability */
	int ret;

	/********** Input elaboration **********/
	#ifdef __VERBOSE
	trace_printf("Received command cmd_kap_reset.\n");
	#endif
	// No input payload to be used

	eke_kap_reset();

	/********** Output definition **********/
	// Define output payload
	sprintf((char*)payload_buf_out, "KAP state successfully reset.");
	// Define output header
	header_buf_out.err_code = OUT_ERR_NOERR;
	header_buf_out.length = strlen((char*)payload_buf_out) + 1; //include '\0' of sprintf

	/************ Send response ************/
	// Write header
	ret = write_header_chout(header_buf_out);
	if(ret)
		return -1;
	// Write payload
	ret = write_payload_chout(header_buf_out.length);
	if(ret)
		return -1;

	return header_buf_out.length;
}
