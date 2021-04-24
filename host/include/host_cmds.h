#ifndef __host_commands_H
#define __host_commands_H

#include <stdint.h>


/*
 * DEVICE COMMANDS LIBRARY
 * -----------------------
 * This library implements the Host-side functions to send the desired command to the
 * Device. Such functions manages the whole procedure to send a command to the Device
 * and the received response: they fill the input header to write to input channel
 * and manage the communication, receiving the response and returning it to the
 * caller. Beware that all functions to send commands defined in this library must
 * correspond to opcodes whose commands are correctly recognised and implemented by
 * the Device, in its library devive_cmds.
 *
 * In order for an application to use the functionalities provided by the device
 * through this communication library, it must provide:
 * + a SPACE ALLOCATED for the response (i.e. a response array, depending on the king
 *   of output of the command)
 * + the parameters needed by the command to fill the command input header (i.e. the
 *   payload to attach to cmd, the payload length, the optional flags, the key id to
 *   be used for crypto functions and the key size if needed)
 * With those, the host must only call the function related to the desired command.
 */


/*********************************** DATA TYPES ************************************/

/* Declaration of all known cmds opcodes (must agree with host) */
typedef enum {
	OPCODE_NOP = 0,
	OPCODE_TEST_PING = 1,
	OPCODE_TEST_PAYLOAD = 2,
	OPCODE_ENCRYPT = 3,
	OPCODE_DECRYPT = 4,
	OPCODE_HMAC_SIGN = 5,
	OPCODE_HMAC_CHECK = 6,
	OPCODE_ADD_KEY = 7,
	OPCODE_REMOVE_KEY = 8,
	OPCODE_UPDATE_KEY = 9,
	OPCODE_LIST_KEYS = 10,
	OPCODE_ACTIVATE_KEY = 11,
	OPCODE_SUSPEND_KEY = 12,
	OPCODE_DEACTIVATE_KEY = 13,
	OPCODE_COMPRIMISE_KEY = 14,
	OPCODE_DESTROY_KEY = 15,
	OPCODE_KAP_1A = 16,
	OPCODE_KAP_2B = 17,
	OPCODE_KAP_3A = 18,
	OPCODE_KAP_4B = 19,
	OPCODE_KAP_5A = 20,
	OPCODE_KAP_6B = 21,
	OPCODE_KAP_RESET = 22
} cmd_opcode_t;

/* Flags for the AES-256 cmd_encrypt/cmd_decrypt */
typedef enum {
	AES_ECB_MODE = 0,
	AES_CBC_MODE = 1
} aes_mode_t;

/****************************** FUNCTIONS PROTOTYPES *******************************/

/* Commands functions, to send them and receive response */
int cmd_test_ping(uint8_t device_id, uint8_t *response, uint16_t *response_len_p);
int cmd_test_payload(uint8_t device_id, uint8_t *response, uint16_t *response_len_p);

int cmd_encrypt(uint8_t device_id, uint8_t *payload, uint16_t payload_len, aes_mode_t aes_mode, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_decrypt(uint8_t device_id, uint8_t *payload, uint16_t payload_len, aes_mode_t aes_mode, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_hmac_sign(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_hmac_check(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);

int cmd_add_key(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint16_t  key_size, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p);
int cmd_remove_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_update_key(uint8_t device_id, uint8_t *payload, uint16_t payload_len, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p);
int cmd_list_keys(uint8_t device_id, uint8_t *response, uint16_t *response_len_p);

int cmd_activate_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_suspend_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_deactivate_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_compromise_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);
int cmd_destroy_key(uint8_t device_id, uint32_t key_id, uint8_t *response, uint16_t *response_len_p);

int cmd_kap_1a(uint8_t device_id, uint32_t *beta_p, uint32_t *alpha_p, uint8_t *enc_pow_a, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_2b(uint8_t device_id, uint16_t key_size, uint32_t beta, uint32_t alpha, uint8_t *enc_pow_a, uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_3a(uint8_t device_id, uint16_t key_size, uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint8_t *enc_reply_a, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_4b(uint8_t device_id, uint8_t *enc_reply_a, uint8_t *enc_reply_b, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_5a(uint8_t device_id, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *enc_reply_b, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_6b(uint8_t device_id, uint32_t key_id, uint32_t key_cryptoperiod, uint8_t *response, uint16_t *response_len_p);
int cmd_kap_reset(uint8_t device_id, uint8_t *response, uint16_t *response_len_p);

#endif /* __host_commands_H */