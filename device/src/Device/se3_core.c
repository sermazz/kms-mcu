#include "se3_core.h"
#include "se3_communication_core.h"
#include "crc16.h"
#include "se3_common.h"

// For trace_printf
#include "diag/Trace.h"
// My libraries
#include <device_cmds.h>
#include <com_channel.h>
#include <nv_mem.h>
#include <kms.h>
#include <rng_custom.h>
#include <eke_exp.h>

/*
 * COMMUNICATION THROUGH ARM SEMIHOSTING CHANNEL FILES - How To
 * ------------------------------------------------------------
 * In order for a correct communication between an host (represented by another C
 * program) and the emulated device to happen, you must first build and run this
 * project, so that the files for the input/output communication channels are
 * created and initialized, without any other process on the emulating machine
 * trying to access it. Afterwards, when the device enters its device_loop(), the
 * host program to write the input channel file can be executed, with the device
 * ready to correctly acknowledge incoming changes on such file and possibly
 * respond on the output channel file.
 */


/************************************* DEFINES *************************************/

//#define __DEBUG          /* Enable trace_printf debug information */
#define __VERBOSE        /* Enable verbose trace_printf system information */


/********************************* EXTERN VARIABLES ********************************/

/* From com_channel.c */
extern const struct cmd_header nop_cmd;
extern const struct out_header no_output;


/******************************** STATIC PROTOTYPES ********************************/

static void abort_execution();


/****************************** DEVICE INITIALIZATION ******************************/

/* Device initialization */
void device_init()
{
	struct out_header test_output;
	struct cmd_header test_input;

	int ret;
	int init_fail = 0;        // "0" if init successful, "true" or "-1" otherwise
	nvm_init_t nvm_init_ret;  // tells whether NV memory is initialized for first time or already existed

	/************ Communication initialization ************/

	#ifdef __VERBOSE
	trace_printf("Initializing ARM Semihosting communication channels...\n");
	#endif

	/*
	 * Initialize output channel file: create or reset channel_out file and
	 * initialize to EMPTY output header, finally testing correct initialization
	 */

	/* Create file with empty header */
	init_fail = reset_chout();
	/* First read of initialized output channel file, to test initialization */
	ret = read_header_chout(&test_output);
	/* Test initialization */
	if (ret || test_output.length != no_output.length){
		#ifdef __VERBOSE
		trace_printf("Output channel was not correctly initialized.\n");
		#endif
		init_fail = true;
	}

	/*
	 * Initialize input channel file: create or reset channel_in file and initialize
	 * to NOP cmd header, finally testing correct initialization
	 */

	/* Create file with empty header */
	init_fail = reset_chin();
	/* First read of initialized input channel file, to test initialization */
	ret = read_header_chin(&test_input);
	/* Test initialization */
	if (ret || test_input.cmd != nop_cmd.cmd || test_input.flags != nop_cmd.flags || test_input.key_id != nop_cmd.key_id || test_input.length != nop_cmd.length){
		#ifdef __VERBOSE
		trace_printf("Input channel was not correctly initialized.\n");
		#endif
		init_fail = true;
	}

	/************ Non-volatile Flash memory init ************/

	#ifdef __VERBOSE
	trace_printf("Initializing non-volatile Flash memory...\n");
	#endif

	nvm_init_ret = init_nvm();
	if (nvm_init_ret == NVM_INIT_ERROR) {
		#ifdef __VERBOSE
		trace_printf("Flash memory was not correctly initialized.\n");
		#endif
		init_fail = true;
	}

	/************ Custom Random Numbers Generator init ************/

	#ifdef __VERBOSE
	trace_printf("Initializing Random Numbers Generator...\n");
	#endif

	ret = init_rng();
	if (ret){
		#ifdef __VERBOSE
		trace_printf("Random Numbers Generator was not correctly initialized.\n");
		#endif
		init_fail = true;
	}

	/************ Key Management System init ************/

	#ifdef __VERBOSE
	trace_printf("Initializing Key Management System...\n");
	#endif

	ret = kms_init(nvm_init_ret);
	if (ret){
		#ifdef __VERBOSE
		trace_printf("Key Management System was not correctly initialized.\n");
		#endif
		init_fail = true;
	}

	/************ Encrypted Key Exchange protocol init ************/

	#ifdef __VERBOSE
	trace_printf("Initializing Encrypted Key Exchange protocol...\n");
	#endif

	eke_init();

	/************ Handle initializazion fail ************/

	/*
	 * May happen if the file already existed before initialization and is already
	 * kept busy by the host process, or if for some reason the host software was
	 * launched before the device emulator and it already created the channel file
	 * and put in listening to it.
	 */

	if(init_fail)
		abort_execution();

	#ifdef __VERBOSE
	trace_printf("Initialization completed.\n\n");
	#endif
}


/****************************** DEVICE FUNCTIONALITY *******************************/

/* Device functionality */
void device_loop()
{
	struct cmd_header header_buf_in;  /* Buffer for input command header */

	int ret;
	uint8_t cmd_sent;

	/* Infinite device loop */
	for (;;) {

		/************ Poll input channel file ************/

		/*
		 * This read is the very piece of code executed at every iteration: it gets
		 * executed always, until a change in the input channel file (i.e. a new cmd)
		 * is detected; the host program, when desiring to send a command, accesses
		 * the input channel file once and writes it, subsequently going in wait for
		 * an answer, for a given timeout.
		 * While the host waits, the device detects the change in the file on the
		 * next polling iteration, decoding the command, executing it and possibly
		 * sending an answer.
		 * Note that no race condition can happen on the input channel file at this
		 * step because the device only accesses it in reading mode, while the host
		 * is the only one able to write it.
		 *
		 * Normally (when no command is being issued), channel_in (input channel
		 * file) contains a NOP command; if the device reads an header and it is
		 * different from a NOP header, it means that a new command has been sent by
		 * the host. If a NOP is received nothing happens. The received command is
		 * overwritten by a NOP (i.e. it gets consumed) by the device after its
		 * reception so that a new subsequent command can be received and correctly
		 * detected after that one.
		 */

		/* Fetch header from channel_in */
		ret = read_header_chin(&header_buf_in);
		if (ret)
			abort_execution();

		#ifdef __DEBUG
		trace_printf("\nReceived header_buf_in = | %u | %u | %u | %u | %u |\n", header_buf_in.cmd, header_buf_in.flags, header_buf_in.key_id, header_buf_in.key_size, header_buf_in.length);
		#endif

		/************ Check if new incoming cmd ************/

		/* Check header different from NOP header */
		if(header_buf_in.cmd != nop_cmd.cmd){
			#ifdef __VERBOSE
			trace_printf("New command in input buffer (%u bytes payload).\n", header_buf_in.length);
			#endif

			/* Fetch payload in payload_buf_in, if any */
			if(header_buf_in.length != 0){
				ret = read_payload_chin(header_buf_in.length);
				if (ret)
					abort_execution();
			}

			/************ Consume the newly received input command ************/

			/*
			 * At this step, the host should be still waiting for a response after
			 * having sent the command that the device has just received, so there
			 * cannot be a race condition on the input channel file (even if the
			 * device should only read and not write channel_in), because the host
			 * will not try to write again on channel_in until next command.
			 */

			ret = reset_chin();
			if(ret)
				abort_execution();

			/************ Decode and execute received command ************/

			/*
			 * The device tries to match the opcode of the received command with a
			 * known one, performing the corresponding operation.
			 */
			cmd_sent = 1;

			switch(header_buf_in.cmd){
				/* Test command 1 */
				case OPCODE_TEST_PING:
					ret = cmd_test_ping();
					break;

				/* Test command 2 */
				case OPCODE_TEST_PAYLOAD:
					ret = cmd_test_payload(header_buf_in.length);
					break;

				/* Command AES-256 CBC encryption */
				case OPCODE_ENCRYPT:
					ret = cmd_encrypt(header_buf_in.length, header_buf_in.key_id, header_buf_in.flags);
					break;

				/* Command AES-256 CBC decryption */
				case OPCODE_DECRYPT:
					ret = cmd_decrypt(header_buf_in.length, header_buf_in.key_id, header_buf_in.flags);
					break;

				/* Command HMAC-SHA256_SIGN */
				case OPCODE_HMAC_SIGN:
					ret = cmd_hmac_sign(header_buf_in.length, header_buf_in.key_id);
					break;

				/* Command HMAC-SHA256_CHECK */
				case OPCODE_HMAC_CHECK:
					ret = cmd_hmac_check(header_buf_in.length, header_buf_in.key_id);
					break;

				/* Command Add new cryptographic key */
				case OPCODE_ADD_KEY:
					ret = cmd_add_key(header_buf_in.length, header_buf_in.key_id, header_buf_in.key_size, header_buf_in.key_cryptoperiod);
					break;

				/* Command Remove cryptographic key */
				case OPCODE_REMOVE_KEY:
					ret = cmd_remove_key(header_buf_in.key_id);
					break;

				/* Command Reseed cryptographic key */
				case OPCODE_UPDATE_KEY:
					ret = cmd_update_key(header_buf_in.length, header_buf_in.key_id, header_buf_in.key_cryptoperiod);
					break;

				/* Command List keys in KMS */
				case OPCODE_LIST_KEYS:
					ret = cmd_list_keys();
					break;

				case OPCODE_ACTIVATE_KEY:
					ret = cmd_activate_key(header_buf_in.key_id);
					break;

				case OPCODE_SUSPEND_KEY:
					ret = cmd_suspend_key(header_buf_in.key_id);
					break;

				case OPCODE_DEACTIVATE_KEY:
					ret = cmd_deactivate_key(header_buf_in.key_id);
					break;

				case OPCODE_COMPRIMISE_KEY:
					ret = cmd_compromise_key(header_buf_in.key_id);
					break;

				case OPCODE_DESTROY_KEY:
					ret = cmd_destroy_key(header_buf_in.key_id);
					break;				

				/* Step #1 (device A) of KAP */
				case OPCODE_KAP_1A:
					ret = cmd_kap_1a();
					break;

				/* Step #2 (device B) of KAP */
				case OPCODE_KAP_2B:
					ret = cmd_kap_2b(header_buf_in.length, header_buf_in.key_size);
					break;

				/* Step #3 (device B) of KAP */
				case OPCODE_KAP_3A:
					ret = cmd_kap_3a(header_buf_in.length, header_buf_in.key_size);
					break;

				/* Step #4 (device A) of KAP */
				case OPCODE_KAP_4B:
					ret = cmd_kap_4b(header_buf_in.length);
					break;


				/* Step #5 (device B) of KAP */
				case OPCODE_KAP_5A:
					ret = cmd_kap_5a(header_buf_in.length, header_buf_in.key_id, header_buf_in.key_cryptoperiod);
					break;


				/* Step #6 (device A) of KAP */
				case OPCODE_KAP_6B:
					ret = cmd_kap_6b(header_buf_in.key_id, header_buf_in.key_cryptoperiod);
					break;
					
				/* Command reset KAP state */
				case OPCODE_KAP_RESET:
					ret = cmd_kap_reset(header_buf_in.length);
					break;

				/* No command */
				default:
					// The received opcode does not match any implemented device command
					#ifdef __VERBOSE
					trace_printf("No commands matching the received opcode.\n");
					#endif
					cmd_sent = 0;
					// Reset output channel, just to be sure
					ret = reset_chin();
					break;
			}

			/* Handle commands errors */
			if(ret < 0)
				abort_execution();

			#ifdef __VERBOSE
			if(cmd_sent)
				trace_printf("Response sent (%d bytes payload).\n", ret);
			trace_printf("\n");
			#endif
		}
	}
}

/*
 * Function abort_execution
 * ------------------------
 * Goes into an infinite loop to deal with non-handled errors.
 */
static void abort_execution(){
	#ifdef __VERBOSE
	trace_printf("Aborting execution.\n");
	#endif
	while(1){
		/* Infinite loop */
	}
}

static uint16_t invalid_cmd_handler(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    return SE3_ERR_CMD;
}
