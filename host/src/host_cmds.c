#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// My libraries
#include "host_cmds.h"
#include "com_channel.h"

/*
 * DEVICE COMMANDS
 * ---------------
 * Implementation of the library defined in host_cmds.h (see comments in
 * host_cmds.h for further details)
 */


/************************************* DEFINES *************************************/

#define AES_BLOCK_SIZE 16


/********************************* EXTERN VARIABLES ********************************/

/* From com_channel.c */
extern const struct cmd_header nop_cmd;  					   /* NOP for input command in channel_in */


/******************************** STATIC PROTOTYPES ********************************/

static int start_communication(uint8_t device_id, struct cmd_header header_buf_in, uint8_t *payload, struct out_header *hader_buf_out_p, uint8_t *response);


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* Commands functions implementation */

/*
 * All commands functions fill the input header to write in channel_in automatically,
 * basing on their functionality specified by the input arguments and on the payload
 * needed to be sent, again passed as a pointer to an array in the input arguments.
 * Beware that all functions to send commands defined in this library must correspond
 * to opcode whose commands are correctly recognised and implemented by the Device,
 * in the library devive_cmds.h
 * 
 * At the beginning of each command function execution, an header_buf_in structure
 * is declared and initialized to nop_cmd, so that even if not all the fields are
 * assigned some value, the structure written to input channel is still meaningful
 * (this is needed for scalability reasons, since in the future other fields may be
 * added, which were not assigned in old command functions: in this way input header
 * can be modified without modifying definition of old command functions)
 * 
 * All commands functions return:            -1 = if not succesfull
 *                                OUT_ERR_EMPTY = if no response received from device
 *                                OUT_ERR_NOERR = if command concluded succesfully
 *                                OUT_ERR_ERROR = if command concluded with some error
 */


/*
 * Function cmd_test_ping
 * ----------------------
 * Test command #1: ping command which, when received by the device, let it send a
 * dummy response only needed to check if it is alive.
 */
int cmd_test_ping(uint8_t device_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_TEST_PING;
	header_buf_in.flags = 0;
	header_buf_in.key_id = 0;
	header_buf_in.key_size = 0;
	header_buf_in.length = 0;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_test_payload
 * -------------------------
 * Test command #2: it sends a cmd with opcode "2", which has a test payload; the
 * device sends a control string as output test.
 */
int cmd_test_payload(uint8_t device_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	//Define input payload
	uint8_t payload[] = "Test dummy input payload";
	
	//Command to send
	header_buf_in.cmd = OPCODE_TEST_PAYLOAD;
	header_buf_in.flags = 0;
	header_buf_in.key_id = 0;
	header_buf_in.key_size = 0;
	header_buf_in.length = strlen((char*)payload);
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_encrypt
 * --------------------
 * Sends a command with opcode "3" and a plain text, which is encrypted with the
 * AES-256 encryption algorithm in ECB or CBC operating mode, basing on the argument
 * aes_mode; the response array is filled with the corresponding cipher text.
 */
int cmd_encrypt(uint8_t device_id, uint8_t *payload, uint16_t payload_len, aes_mode_t aes_mode, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_ENCRYPT;
	header_buf_in.flags = aes_mode;
	header_buf_in.key_id = key_id;
	header_buf_in.length = payload_len;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_decrypt
 * --------------------
 * Sends a command with opcode "4" and a cipher text encrypted with the AES-256
 * encryption algorithm in ECB or CBC operating mode (specified by the argument
 * aes_mode); the cipher text is decrypted and the corresponding plain text is
 * stored in the response array.
 */
int cmd_decrypt(uint8_t device_id, uint8_t *payload, uint16_t payload_len, aes_mode_t aes_mode, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_DECRYPT;
	header_buf_in.flags = aes_mode;
	header_buf_in.key_id = key_id;
	header_buf_in.length = payload_len;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_hmac_sign
 * -----------------
 * Sends a command with opcode "5" and a payload which is fed as input to a
 * HMAC-SHA-256 algorithm; its response is stored in the response array.
 */
int cmd_hmac_sign(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_HMAC_SIGN;
	header_buf_in.key_id = key_id;
	header_buf_in.length = payload_len;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_hmac_check
 * -----------------
 * Sends a command with opcode "6" and a payload which is fed as input to a
 * HMAC-SHA-256 algorithm; its response is stored in the response array.
 */
int cmd_hmac_check(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_HMAC_CHECK;
	header_buf_in.key_id = key_id;
	header_buf_in.length = payload_len;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_add_key
 * --------------------
 * Sends a command with opcode "7" and a payload which is used as seed to generate a
 * new key in the KMS database of the device; also, the id in the KMS database and
 * the size of the key have to be specified; the response is stored in the response
 * array.
 */
int cmd_add_key(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint16_t  key_size, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_ADD_KEY;
	header_buf_in.key_id = key_id;
	header_buf_in.key_size = key_size;
	header_buf_in.length = payload_len;
	header_buf_in.key_cryptoperiod = key_cryptoperiod;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_remove_key
 * -----------------------
 * Sends a command with opcode "8" and an attached key_id of a key in the device KMS
 * which the user wants to be removed from the database.
 */
int cmd_remove_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_REMOVE_KEY;
	header_buf_in.key_id = key_id;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_update_key
 * -----------------------
 * Sends a command with opcode "9" and a payload which is used as seed to update
 * (i.e. reseed) an existing key in the KMS database of the device keeping its old
 * key size; the chosen key is given by key_id; the response is stored in the
 * response array.
 */
int cmd_update_key(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	
	//Command to send
	header_buf_in.cmd = OPCODE_UPDATE_KEY;
	header_buf_in.key_id = key_id;
	header_buf_in.length = payload_len;
	header_buf_in.key_cryptoperiod = key_cryptoperiod;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_list_keys
 * ----------------------
 * Sends a command with opcode "10" which requests a list of the IDs of all the valid
 * keys stored in the KMS of the device; the list is returned in the usual response
 * array of uint8_t containing *(response_len_p) bytes, but it is to be interpreted
 * from the caller as an uint32_t array of *(response_len_p)/sizeof(uint32_t) elements
 * Basically, all bytes of the response are grouped four by four, and each word of 4
 * bytes represent the ID of one of the valid keys in the KMS database of the device
 */
int cmd_list_keys(uint8_t device_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_LIST_KEYS;
	// all other fields set to 0
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_activate_key
 * ----------------------
 * Sends a command with opcode "11" and key_id to
 * activate a key, if possible according to the state diagram
 * of the key status lifecycle.
 */ 
int cmd_activate_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	 
	//Command to send
	header_buf_in.cmd = OPCODE_ACTIVATE_KEY;
	header_buf_in.key_id = key_id;
	
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_suspend_key
 * ----------------------
 * Sends a command with opcode "12" and key_id to
 * suspend a key, if possible according to the state diagram
 * of the key status lifecycle.
 */ 
int cmd_suspend_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	 
	//Command to send
	header_buf_in.cmd = OPCODE_SUSPEND_KEY;
	header_buf_in.key_id = key_id;
	
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_activate_key
 * ----------------------
 * Sends a command with opcode "13" and key_id to
 * deactivate a key, if possible according to the state diagram
 * of the key status lifecycle.
 */ 
int cmd_deactivate_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	 
	//Command to send
	header_buf_in.cmd = OPCODE_DEACTIVATE_KEY;
	header_buf_in.key_id = key_id;
	
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_compromise_key
 * ----------------------
 * Sends a command with opcode "14" and key_id to
 * compromise a key, if possible according to the state diagram
 * of the key status lifecycle.
 */ 
int cmd_compromise_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	 
	//Command to send
	header_buf_in.cmd = OPCODE_COMPRIMISE_KEY;
	header_buf_in.key_id = key_id;
	
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_destroy_key
 * ----------------------
 * Sends a command with opcode "15" and key_id to
 * destroy a key, if possible according to the state diagram
 * of the key status lifecycle.
 */ 
int cmd_destroy_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	 
	//Command to send
	header_buf_in.cmd = OPCODE_DESTROY_KEY;
	header_buf_in.key_id = key_id;
	
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_1a
 * -------------------
 * Sends a command with opcode "10" which launches the step #1 of the KAP for
 * Encrypted Key Exchange on the device A, identified by device_id; the device
 * response is returned in the array pointed by response. When no errors occur, the
 * parameters generated and received by device A are also returned in the variables
 * pointed by beta_p, alpha_p and enc_pow_a.
 * The caller must allocate a 16-element array of uint8_t for enc_pow_a.
 * 
 * Structure of payload sent to device:
 * N/D
 * Structure of payload received from device:
 * | beta (4 bytes) | alpha (4 bytes) | encrypted exponentiation A (16 bytes) |
 */
int cmd_kap_1a(uint8_t device_id, uint32_t *beta_p, uint32_t *alpha_p, uint8_t *enc_pow_a, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_1A;
	// all other fields set to 0
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	// Decode received payload
	if (header_buf_out.err_code == OUT_ERR_NOERR){
		if (header_buf_out.length == 2*sizeof(uint32_t) + AES_BLOCK_SIZE){
			memcpy((void*)beta_p, (void*)response, sizeof(uint32_t));
			memcpy((void*)alpha_p, (void*)(response + sizeof(uint32_t)), sizeof(uint32_t));
			memcpy((void*)enc_pow_a, (void*)(response + 2*sizeof(uint32_t)), AES_BLOCK_SIZE);
		} else {
			// Should never happen if @ device-side everything is handled correctly, i.e. the
			// output payload size should always be the expected one if err_code == OUT_ERR_NOERR
			return -1;
		}
	}
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_2b
 * -------------------
 * Sends a command with opcode "11" which launches the step #2 of the KAP for
 * Encrypted Key Exchange on the device B, identified by device_id; the device
 * response is returned in the array pointed by response. With this command a payload
 * corresponding to the encoded exponentiation received from device A in the step #1
 * is sent to device B (array of 16 uint8_t pointed by enc_pow_a), which then replies
 * with its own result of the exponentiation (returned in the array of 16 uint8_t
 * pointed by enc_pow_b), encrypted with the common password, and with a random
 * challenge (returned in the 16-element array of uint8_t pointed enc_chlg_b),
 * encrypted with the new key on which the devices should agree. Also parameters
 * beta and alpha communicated in plain text by device A are sent to B.
 * 
 * Structure of payload sent to device:
 * | beta (4 bytes) | alpha (4 bytes) | encrypted exponentiation A (16 bytes) |
 * Structure of payload received from device:
 * | encrypted exponentiation B (16 bytes) | encrypted challenge B (16 bytes) |
 */
int cmd_kap_2b(uint8_t device_id, uint16_t key_size, uint32_t beta, uint32_t alpha, uint8_t *enc_pow_a, uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t payload[2*sizeof(uint32_t) + AES_BLOCK_SIZE];
	
	// Assemble payload
	memcpy((void*)payload, (void*)(&beta), sizeof(uint32_t));
	memcpy((void*)(payload + sizeof(uint32_t)), (void*)(&alpha), sizeof(uint32_t));
	memcpy((void*)(payload + 2*sizeof(uint32_t)), (void*)enc_pow_a, AES_BLOCK_SIZE);
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_2B;
	header_buf_in.key_size = key_size;
	header_buf_in.length = 2*sizeof(uint32_t) + AES_BLOCK_SIZE;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	// Decode received payload
	if(header_buf_out.err_code == OUT_ERR_NOERR){
		if (header_buf_out.length == 2*AES_BLOCK_SIZE){
			memcpy((void*)enc_pow_b, (void*)response, AES_BLOCK_SIZE);
			memcpy((void*)enc_chlg_b, (void*)(response + AES_BLOCK_SIZE), AES_BLOCK_SIZE);
		} else {
			// Should never happen if @ device-side everything is handled correctly, i.e. the
			// output payload size should always be the expected one if err_code == OUT_ERR_NOERR
			return -1;
		}
	}
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_3a
 * -------------------
 * Sends a command with opcode "12" which launches the step #3 of the KAP for
 * Encrypted Key Exchange on the device A, identified by device_id; the device
 * response is returned in the array pointed by response. With this command a payload
 * is sent to device A containing the exponentiation computed by device B, encrypted
 * with the common password (array of 16 uint8_t pointed by enc_pow_b), and the
 * random challenge generated by device B encrypted with the newly agreed key (array
 * of 16 uint8_t pointed by enc_chlg_b). The device A replies with an encrypted 16-byte
 * reply (array of 16 uint8_t pointed by enc_reply_a) originated by the concatenation
 * of two uint32_t, namely {reply to B challenge, random challenge A}, encrypted with
 * the newly agreed key.
 * 
 * Structure of payload sent to device:
 * | encrypted exponentiation B (16 bytes) | encrypted challenge B (16 bytes) |
 * Structure of payload received from device:
 * | encrypted {reply to challenge from B, challenge A} (16 bytes) |
 */
int cmd_kap_3a(uint8_t device_id, uint16_t key_size, uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint8_t *enc_reply_a, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t payload[2*AES_BLOCK_SIZE];
	
	// Assemble payload
	memcpy((void*)payload, (void*)enc_pow_b, AES_BLOCK_SIZE);
	memcpy((void*)(payload + AES_BLOCK_SIZE), (void*)enc_chlg_b, AES_BLOCK_SIZE);
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_3A;
	header_buf_in.key_size = key_size;
	header_buf_in.length = 2*AES_BLOCK_SIZE;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	// Decode received payload
	if(header_buf_out.err_code == OUT_ERR_NOERR){
		if (header_buf_out.length == AES_BLOCK_SIZE){
			memcpy((void*)enc_reply_a, (void*)response, AES_BLOCK_SIZE);
		} else {
			// Should never happen if @ device-side everything is handled correctly, i.e. the
			// output payload size should always be the expected one if err_code == OUT_ERR_NOERR
			return -1;
		}
	}
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_4b
 * -------------------
 * Sends a command with opcode "13" which launches the step #4 of the KAP for
 * Encrypted Key Exchange on the device B, identified by device_id; the device
 * response is returned in the array pointed by response. With this command a payload
 * is sent to device B containing the reply generated by device A in its step #3, in
 * turn containing the data {reply to challenge from B, challenge A} concatenated and
 * encrypted (array of 16 uint8_t pointed by enc_reply_a). The device B decrypts such
 * data with the shared new key and, if the solution to its challenge is correct, it
 * replies with an encrypted solution to the challenge generated by A in step #3
 * (array of 16 uint8_t pointed by enc_reply_b).
 * 
 * Structure of payload sent to device:
 * | encrypted {reply to challenge from B, challenge A} (16 bytes) |
 * Structure of payload received from device:
 * | encrypted reply to challenge from A (16 bytes) |
 */
int cmd_kap_4b(uint8_t device_id, uint8_t *enc_reply_a, uint8_t *enc_reply_b, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t payload[AES_BLOCK_SIZE];
	
	// Assemble payload
	memcpy((void*)payload, (void*)enc_reply_a, AES_BLOCK_SIZE);
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_4B;
	header_buf_in.length = AES_BLOCK_SIZE;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	// Decode received payload
	if(header_buf_out.err_code == OUT_ERR_NOERR){
		if (header_buf_out.length == AES_BLOCK_SIZE){
			memcpy((void*)enc_reply_b, (void*)response, AES_BLOCK_SIZE);
		} else {
			// Should never happen if @ device-side everything is handled correctly, i.e. the
			// output payload size should always be the expected one if err_code == OUT_ERR_NOERR
			return -1;
		}
	}
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_5a
 * -------------------
 * Sends a command with opcode "14" which launches the step #5 of the KAP for
 * Encrypted Key Exchange on the device A, identified by device_id; the device
 * response is returned in the array pointed by response.
 * The device verifies whether the replied for the challenge is correct and, if so,
 * stores the shared key on which the two parties agreed upon; the successful result
 * is then communicated to the host with the error code OUT_ERR_NOERR. It is duty of
 * the host to communicate to the other device (device B) that the operation has
 * concluded successfully and it can store the key in its KMS in the same way.
 * 
 * Structure of payload sent to device:
 * | encrypted reply to challenge from A (16 bytes) |
 */
int cmd_kap_5a(uint8_t device_id, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *enc_reply_b, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t payload[AES_BLOCK_SIZE];
	
	// Assemble payload
	memcpy((void*)payload, (void*)enc_reply_b, AES_BLOCK_SIZE);
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_5A;
	header_buf_in.key_id = key_id;
	header_buf_in.length = AES_BLOCK_SIZE;
	header_buf_in.key_cryptoperiod = key_cryptoperiod;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_6b
 * -------------------
 * Sends a command with opcode "15" which launches the step #6 of the KAP for
 * Encrypted Key Exchange on the device B, identified by device_id; the device
 * response is returned in the array pointed by response.
 * This command is used to send a positive acknowledgment to device B that device A
 * confirmed that the challenge reply is correct and the shared key on which the two
 * parties agreed upon is correct and can be stored and used.
 */
int cmd_kap_6b(uint8_t device_id, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_6B;
	header_buf_in.key_id = key_id;
	header_buf_in.key_cryptoperiod = key_cryptoperiod;
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/*
 * Function cmd_kap_reset
 * ----------------------
 * Sends a command with opcode "16" which resets the state of the KAP protocol on the
 * device identified by device_id; the device response is returned in the array
 * pointed by response.
 */
int cmd_kap_reset(uint8_t device_id, uint8_t *response, uint16_t *response_len_p)
{
	int ret;
	struct cmd_header header_buf_in = nop_cmd; // initialize to nop for scalability
	struct out_header header_buf_out;
	uint8_t *payload = NULL;  // dummy input payload array
	
	//Command to send
	header_buf_in.cmd = OPCODE_KAP_RESET;
	// all other fields set to 0
	
	/* Send command and receive response*/
	ret = start_communication(device_id, header_buf_in, payload, &header_buf_out, response);
	if(ret)
		return -1;

	*(response_len_p) = header_buf_out.length;
	return header_buf_out.err_code;
}

/* Other functions */

/*
 * Function start_communication
 * ----------------------------
 * Performs all the steps needed to communicate with the device: it issues a command
 * sent over the interface with the device, check the output channel, consumes the
 * received output response and writes it in a given output buffer for the host.
 * Since the steps are always the same fore very command, they are enclosed in this
 * function for the sake of usability.
 * It returns: 0 if communication is successful, otherwise -1
 */
static int start_communication(uint8_t device_id, struct cmd_header header_buf_in, uint8_t *payload, struct out_header *hader_buf_out_p, uint8_t *response)
{
	int ret;

	// Reset output channel file before issuing cmd just to be safe
	// (so that we are sure the output channel is empty at the beginning
	//  of the communication, to correctly detect "no response received")
	ret = reset_choutfile(device_id);
	if(ret)
		return -1;
	// Send command
	ret = send_command(device_id, header_buf_in, payload);
	if(ret)
		return -1;
	// Check output and receive response
	ret = check_output(device_id, hader_buf_out_p, response);
	if(ret)
		return -1;
	// Consume output response from device
	ret = reset_choutfile(device_id);
	if(ret)
		return -1;
	
	return 0;
}
