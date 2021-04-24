#ifndef __device_cmds_H
#define __device_cmds_H

/*
 * DEVICE COMMANDS LIBRARY
 * -----------------------
 * This library implements the behavior of the commands which are known and can be
 * executed by the device. Such commands, whose opcode corresponds to the cmd field
 * of the received cmd_header structure, can access the payload received in the input
 * channel, saved in an internal buffer, and write the output channel by means of an
 * interface towards the communication channel, basing on the result produced by the
 * command itself.
 *
 * Each commands perform the same steps of inputs reading (flags, input payload),
 * output computation (output payload, output payload size) and response transmission
 * Basing on the required input, each function implementing a different command may
 * show different required input arguments 9 (i.e. input payload and flags).
 * The decode of the flags is done directly in se3_core.c, with flags types defined
 * in this device_cmds.h library.
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

/* AES encryption/decryption flags */
typedef enum {
	AES_ECB_MODE = 0,
	AES_CBC_MODE = 1
} aes_mode_t;


/****************************** FUNCTIONS PROTOTYPES *******************************/

/* Commands execution functions */
int cmd_test_ping();
int cmd_test_payload(uint16_t payload_in_len);

int cmd_encrypt(uint16_t payload_in_len, uint32_t key_id, uint16_t flags);
int cmd_decrypt(uint16_t payload_in_len, uint32_t key_id, uint16_t flags);
int cmd_hmac_sign(uint16_t payload_in_len, uint32_t key_id);
int cmd_hmac_check(uint16_t payload_in_len, uint32_t key_id);

int cmd_add_key(uint16_t payload_in_len, uint32_t key_id, uint16_t key_size, uint32_t key_cryptoperiod);
int cmd_remove_key(uint32_t key_id);
int cmd_update_key(uint16_t payload_in_len, uint32_t key_id, uint32_t key_cryptoperiod);
int cmd_list_keys();

int cmd_activate_key(uint32_t key_id);
int cmd_suspend_key(uint32_t key_id);
int cmd_deactivate_key(uint32_t key_id);
int cmd_compromise_key(uint32_t key_id);
int cmd_destroy_key(uint32_t key_id);

int cmd_kap_1a();
int cmd_kap_2b(uint16_t payload_in_len, uint16_t key_size);
int cmd_kap_3a(uint16_t payload_in_len, uint16_t key_size);
int cmd_kap_4b(uint16_t payload_in_len);
int cmd_kap_5a(uint16_t payload_in_len, uint32_t key_id, uint32_t key_cryptoperiod);
int cmd_kap_6b(uint32_t key_id, uint32_t key_cryptoperiod);
int cmd_kap_reset();

#endif /* __device_cmds_H */
