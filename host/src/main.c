/*
 * This program must be executed only after the device emulator has been started,
 * and it is already constantly monitoring the initialized input channel file.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// My libraries
#include "host_cmds.h"
#include "com_channel.h"

#define HASH_OUTPUT_LEN 32

/* Static prototypes */
static int hexstr2bytes(char *input_str, uint8_t *output_array);
static void input_payload(uint8_t *output);
static void input_hexpayload(char *output);

/* Main - wrapper to send cmd
 * --------------------------
 * This main is a wrapper for the host_cmds library meant to test the crypto
 * functions implemented inside the device and its Key Management System
 * functionalities. This program presents an interactive textual interface
 * with several input section to customize the commands packets to send to the
 * device; outut responses from the device are displayer on stdout basing on
 * the outcome of the operation
 */
int main(){
	// Input payload to send to Device
	char payload[PAYLOAD_BUF_IN_SIZE + 1]; // +1 for the '\0' for string management
	
	// Strncat dest: since it will accomodate the payload, it must be large enough
	char digest[HASH_OUTPUT_LEN + PAYLOAD_BUF_IN_SIZE + 1];

	uint16_t payload_len, digest_len;
	// Array to write device response
	char response[PAYLOAD_BUF_OUT_SIZE + 1];
	uint16_t response_len;
	// Input cmd parameters
	uint32_t key_id;
	uint16_t key_size;
	uint32_t key_cryptoperiod;
	aes_mode_t cipher_mode;
	// Destination device choice
	uint8_t device_id;

	// Buffers for key-agreement protocol
	uint32_t beta, alpha; // KAP parameters
	uint8_t enc_pow_a[16], enc_pow_b[16]; // encrypted exponentiations results from devices A and B
	uint8_t enc_chlg_b[16]; // encrypted random challenge from device B
	uint8_t enc_reply_a[16], enc_reply_b[16]; // encrypted replies from devices A and B

	// to take input payload as hex string
	char payload_hexchar[PAYLOAD_BUF_IN_SIZE*2 + 1], digest_hexchar[PAYLOAD_BUF_IN_SIZE*2 + 1];
	// switch-case variables
	int cmd_choice, cipher_choice, input_choice;

	int i;
	int cmd_ret;
	int command_taken;

	while(1){
		command_taken = 1;
		
		printf("-----------------------\n");
		printf("--- SECube commands ---\n");
		printf("-----------------------\n");
		printf("[1] test ping\n");
		printf("[2] test payload\n");
		printf("[3] AES-256 encryption\n");
		printf("[4] AES-256 decryption\n");
		printf("[5] HMAC-SHA256 sign\n");
		printf("[6] HMAC-SHA256 check\n");
		printf("[7] add key to KMS\n");
		printf("[8] remove key from KMS\n");
		printf("[9] update key in KMS\n");
		printf("[10] list KMS keys\n");
		printf("[11] activate key\n");
		printf("[12] suspend key\n");
		printf("[13] deactivate key\n");
		printf("[14] compromise key\n");
		printf("[15] destroy key\n");
		printf("[16] launch KAP step #1 (A)\n");
		printf("[17] launch KAP step #2 (B)\n");
		printf("[18] launch KAP step #3 (A)\n");
		printf("[19] launch KAP step #4 (B)\n");
		printf("[20] launch KAP step #5 (A)\n");
		printf("[21] launch KAP step #6 (B)\n");
		printf("[22] reset KAP state\n");
		printf("[0] exit\n");
		printf("-----------------------\n");
		printf("Insert your choice: ");
		scanf("%d", &cmd_choice);
		getchar(); //consume '\n' in stdin buffer
		printf("---------------------------\n\n");
		
		switch(cmd_choice){
			case 0:
				// exit from program
				return 0;
				
			case 1:
				printf("Issuing command cmd_test_ping.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_test_ping(device_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response); // -1 to discard EOF from %.*s
				}
				break;
				
			case 2:
				printf("Issuing command cmd_test_payload.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				sprintf((char*)payload, "Test dummy input payload");
				payload_len = strlen((char*)payload);
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_test_payload(device_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 3:
				printf("Issuing command cmd_encrypt.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				printf("\nHow would you like to insert the plain text?\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert plain text (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						break;
					case 2:
						printf("Insert plain text (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Flags
				printf("\nSelect cipher mode:");
				printf("\n[1] ECB");
				printf("\n[2] CBC\n");
				printf("Insert your choice: ");
				scanf("%d", &cipher_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(cipher_choice){
					case 1:
						cipher_mode = AES_ECB_MODE;
						break;
					case 2:
						cipher_mode = AES_CBC_MODE;
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert encryption key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_encrypt(device_id, payload, payload_len, cipher_mode, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
					printf("Device response (hexadecimal):\n");
					for(i = 0; i < response_len; i++)
						printf("%02x", (uint8_t)response[i]);
					printf("\n");
				}
				break;

			case 4:
				printf("Issuing command cmd_decrypt.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				printf("\nHow would you like to insert the cipher text?\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert cipher text (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						break;
					case 2:
						printf("Insert cipher text (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Flags
				printf("\nSelect cipher mode:");
				printf("\n[1] ECB");
				printf("\n[2] CBC\n");
				printf("Insert your choice: ");
				scanf("%d", &cipher_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(cipher_choice){
					case 1:
						cipher_mode = AES_ECB_MODE;
						break;
					case 2:
						cipher_mode = AES_CBC_MODE;
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert decryption key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_decrypt(device_id, payload, payload_len, cipher_mode, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
					printf("Device response (hexadecimal):\n");
					for(i = 0; i < response_len; i++)
						printf("%02x", (uint8_t)response[i]);
					printf("\n");
				}
				break;
				
			case 5:
				printf("Issuing command cmd_hmac_sign.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				printf("\nHow would you like to insert the message to hash?\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert message (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						if (payload_len > PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN) {
							printf("WARNING: MAX message length is %d Bytes, messages above the limit will signed but cannot be checked in future", PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN);
							return -1;
						}
						break;
					case 2:
						printf("Insert message (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						if (payload_len > PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN) {
							printf("WARNING: MAX message length is %d Bytes, messages above the limit will signed but cannot be checked in future", PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN);
							return -1;
						}
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_hmac_sign(device_id, payload, payload_len, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
					printf("Device response (hexadecimal):\n");
					for(i = 0; i < response_len; i++)
						printf("%02x", (uint8_t)response[i]);
					printf("\n");
				}
				break;

			case 6:
				printf("Issuing command cmd_hmac_check.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Digest
				printf("\nInsert the received HMAC_SHA256 digest\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert digest (string): ");
						input_payload(digest);
						digest_len = strlen((char*)digest);
						if (digest_len != HASH_OUTPUT_LEN) {
							printf("ERROR: Must insert a 32-byte long digest.");
							return -1;
						}
						break;
					case 2:
						printf("Insert digest (hexadecimal): ");
						input_hexpayload(digest_hexchar);
						digest_len = hexstr2bytes(digest_hexchar, digest);
						if (digest_len != HASH_OUTPUT_LEN) {
							printf("ERROR: Must insert a 32-byte long digest.");
							return -1;
						}
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				printf("\nInsert the received message to be checked\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert message (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						if (payload_len > PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN) {
							// error-checking needed here due to non-standard payload_len utilization
							printf("ERROR: Max message length is %d bytes.", PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN);
							return -1;
						}
						break;
					case 2:
						printf("Insert message (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						if (payload_len > PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN) {
							// error-checking needed here due to non-standard payload_len utilization
							printf("ERROR: Max message length is %d bytes.", PAYLOAD_BUF_IN_SIZE-HASH_OUTPUT_LEN);
							return -1;
						}
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Combine digest+payload and store it in the digest variable
				memcpy(&(digest[HASH_OUTPUT_LEN]), payload, payload_len);
				digest[HASH_OUTPUT_LEN+payload_len] = '\0'; 
				digest_len = strlen((char*)digest);
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", digest_len, digest);
				printf("Command sent (%u bytes payload).\n", digest_len);
				cmd_ret = cmd_hmac_check(device_id, digest, digest_len, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 7:
				printf("Issuing command cmd_add_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				printf("\nHow would you like to insert the key seed?\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert new key seed (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						break;
					case 2:
						printf("Insert new key seed (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert new key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				printf("Insert new key size in bytes (uint16): ");
				scanf("%hu", &key_size);
				getchar(); //consume '\n' in stdin buffer
				// Cryptoperiod
				printf("Insert cryptoperiod of new key (uint32): ");
				scanf("%u", &key_cryptoperiod);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_add_key(device_id, payload, payload_len, key_id, key_size, key_cryptoperiod, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 8:
				printf("Issuing command cmd_remove_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_remove_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 9:
				printf("Issuing command cmd_update_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Payload
				printf("\nHow would you like to insert the key seed?\n");
				printf("[1] ASCII string\n");
				printf("[2] Hexadecimal string\n");
				printf("Insert your choice: ");
				scanf("%d", &input_choice);
				getchar(); //consume '\n' in stdin buffer
				switch(input_choice){
					case 1:
						printf("Insert new key seed (string): ");
						input_payload(payload);
						payload_len = strlen((char*)payload);
						break;
					case 2:
						printf("Insert new key seed (hexadecimal): ");
						input_hexpayload(payload_hexchar);
						payload_len = hexstr2bytes(payload_hexchar, payload);
						break;
					default:
						printf("Invalid choice!\n");
						return -1;
				}
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Cryptoperiod
				printf("Insert cryptoperiod of new key (uint32): ");
				scanf("%u", &key_cryptoperiod);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nPayload (string) = \"%.*s\"\n", payload_len, payload);
				printf("Command sent (%u bytes payload).\n", payload_len);
				cmd_ret = cmd_update_key(device_id, payload, payload_len, key_id, key_cryptoperiod, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 10:
				printf("Issuing command cmd_list_keys.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_list_keys(device_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					// Transpose to array of uint32_t & print
					printf("Available keys IDs (uint32_t array): ");
					for (i = 0; i < response_len/sizeof(uint32_t); i++)
						printf("| %u ", *((uint32_t*)response + i));
					printf("|\n");
				}
				break;

			case 11:
				printf("Issuing command cmd_activate_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_activate_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 12:
				printf("Issuing command cmd_suspend_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_suspend_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 13:
				printf("Issuing command cmd_deactivate_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_deactivate_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 14:
				printf("Issuing command cmd_compromise_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_compromise_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 15:
				printf("Issuing command cmd_destroy_key.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_destroy_key(device_id, key_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			case 16:
				printf("Issuing command cmd_kap_1a.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_kap_1a(device_id, &beta, &alpha, enc_pow_a, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("beta (uint32_t) = %u\nalpha (uint32_t) = %u\n", beta, alpha);
					printf("Encrypted alpha^R_a mod beta (hexadecimal):\n");
					for(i = 0; i < 16; i++)
						printf("0x%02x ", (uint8_t)enc_pow_a[i]);
					printf("\n");
				}
				break;
				
			case 17:
				printf("Issuing command cmd_kap_2b.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("Insert new key size in bytes (uint16): ");
				scanf("%hu", &key_size);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%lu bytes payload).\n", 2*sizeof(uint32_t) + 16);
				cmd_ret = cmd_kap_2b(device_id, key_size, beta, alpha, enc_pow_a, enc_pow_b, enc_chlg_b, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Encrypted alpha^R_b mod beta (hexadecimal):\n");
					for(i = 0; i < 16; i++)
						printf("0x%02x ", (uint8_t)enc_pow_b[i]);
					printf("\n");
					printf("Encrypted challenge from B (hexadecimal):\n");
					for(i = 0; i < 16; i++)
						printf("0x%02x ", (uint8_t)enc_chlg_b[i]);
					printf("\n");
				}
				break;
				
			case 18:
				printf("Issuing command cmd_kap_3a.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("Insert new key size in bytes (uint16): ");
				scanf("%hu", &key_size);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 2*16);
				cmd_ret = cmd_kap_3a(device_id, key_size, enc_pow_b, enc_chlg_b, enc_reply_a, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Encrypted {challenge B reply, challenge from A} (hexadecimal):\n");
					for(i = 0; i < 16; i++)
						printf("0x%02x ", (uint8_t)enc_reply_a[i]);
					printf("\n");
				}
				break;
				
			case 19:
				printf("Issuing command cmd_kap_4b.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 16);
				cmd_ret = cmd_kap_4b(device_id, enc_reply_a, enc_reply_b, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Encrypted {challenge B reply, challenge from A} (hexadecimal):\n");
					for(i = 0; i < 16; i++)
						printf("0x%02x ", (uint8_t)enc_reply_b[i]);
					printf("\n");
				}
				break;
				
			case 20:
				printf("Issuing command cmd_kap_5a.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert new key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Cryptoperiod
				printf("Insert cryptoperiod of new key (uint32): ");
				scanf("%u", &key_cryptoperiod);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 16);
				cmd_ret = cmd_kap_5a(device_id, key_id, key_cryptoperiod, enc_reply_b, response, &response_len);;
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 21:
				printf("Issuing command cmd_kap_6b.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Key
				printf("\nInsert new key ID (uint32): ");
				scanf("%u", &key_id);
				getchar(); //consume '\n' in stdin buffer
				// Cryptoperiod
				printf("Insert cryptoperiod of new key (uint32): ");
				scanf("%u", &key_cryptoperiod);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_kap_6b(device_id, key_id, key_cryptoperiod, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;
				
			case 22:
				printf("Issuing command cmd_kap_reset.\n\n");
				// Device ID selection
				printf("Insert receiver device ID (uint8): ");
				scanf("%hhu", &device_id);
				getchar(); //consume '\n' in stdin buffer
				// Send cmd
				printf("\nCommand sent (%u bytes payload).\n", 0);
				cmd_ret = cmd_kap_reset(device_id, response, &response_len);
				// Output
				if(cmd_ret == OUT_ERR_NOERR){
					printf("\nResponse received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
				}
				break;

			default:
				command_taken = 0;
				printf("Invalid choice!\n");
				break;
		}
		
		// only if a command is actually issued
		if(command_taken){
			switch(cmd_ret){
				case OUT_ERR_EMPTY: 
					// empty output after timeout
					printf("\nNo response received from device.\n");
					break;
				case OUT_ERR_NOERR:
					// already handled in each cmd case
					break;
				case OUT_ERR_ERROR:
					// response received with handled error
					printf("\nError response received (%u bytes payload).\n", response_len);
					printf("Device response (string) = \"%.*s\"\n", response_len, response);
					break;
				default:
					// hard fault
					printf("\nAn error occurred during communication with the device.\n\n");
					return -1;
					break;
			}
		}
		
		// Pause
		printf("\nPress RETURN to go back to main menu\n");
		getchar();
	
	}
		
	return 0;
}


/* --------------- Accessory functions --------------- */

/* To convert string of hexadecimal digits (i.e. "1af01ffc6d81") into an array of bytes */
static int hexstr2bytes(char *input_str, uint8_t *output_array){
	unsigned int str_len, bytes_num, i;

	str_len = strlen(input_str);
	/* An even number of hex digits are needed to generate a string of an integer
	 * number of bytes: if the number of hex digit is odd, pad the hex digits string
	 * with a final 0 to represent the last half-byte, and move \0 one char forward */
	if(str_len % 2){
		input_str[str_len] = '0';
		input_str[str_len+1] = '\0'; 
	}

	// number of bytes in array = number of hex digits divided by 2
	// (because each individual byte is represented by 2 hex digits)
	bytes_num = strlen(input_str) / 2;
	// parse
	for(i = 0; i < bytes_num; i++)
		sscanf(input_str + i*2, "%2hhx", (char*)output_array + i);

	return bytes_num;
}

/* Safe way to take a user-defined input string */
static void input_payload(uint8_t *output){
	unsigned int str_len;

	fgets((char*)output, PAYLOAD_BUF_IN_SIZE, stdin);
	str_len = strlen((char*)output);

	// Remove trailing newline, if there.
	if ((str_len > 0) && (output[str_len - 1] == '\n')){
		output[str_len - 1] = '\0';
	}
}

/* Safe way to take a user-defined hex input string */
static void input_hexpayload(char *output){
	unsigned int str_len;

	fgets((char*)output, PAYLOAD_BUF_IN_SIZE*2, stdin);
	str_len = strlen((char*)output);

	// Remove trailing newline, if there.
	if ((str_len > 0) && (output[str_len - 1] == '\n')){
		output[str_len - 1] = '\0';
	}
}