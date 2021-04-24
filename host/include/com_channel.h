#ifndef __com_channel_H
#define __com_channel_H

#include <stdint.h>


/*
 * COMMUNICATION CHANNEL LIBRARY
 * -----------------------------
 * This library implements the interface to the files used to communicate with the
 * emulated Device, by means of the ARM Semihosting mechanism. Since shared binary
 * files are used, the procedures for commands exchange only consist of usual file
 * management functions.
 * In case a new communication mechanism has to be used, the functions defined in
 * this library are the only ones which need to be modified, implementing the correct
 * interface.
 *
 * For this project, a double channel is implemented, employing:
 * - one input channel file for input commands going from Host to Device
 * - one output channel file for communications going from Device to Host
 * Both channel files work as buffers containing only one single input command or
 * output response at a time, which is consumed respectively by the Device and the
 * Host as soon as it gets read; normally, when empty, the channel files contain a
 * dummy content (a NOP cmd, for the input channel file, and an EMPTY output, for the
 * output channel file).
 *
 * ARM Semihosting documentation:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0471g/Bgbjjgij.html
 */


/************************************* DEFINES *************************************/

/* ARM Semihosting communication file */
#define CHFILE_DIR           "../device"      /* must append _deviceidx/ and CHFILE_IN/OUT_NAME */
#define CHFILE_IN_NAME       "channel_in"   /* Input Channel file name */
#define CHFILE_OUT_NAME      "channel_out"  /* Output Channel file name */

/* Payloads buffer limit, due to device limits */
#define PAYLOAD_BUF_IN_SIZE  7600              /* max 7600 bytes of payload */
#define PAYLOAD_BUF_OUT_SIZE 7600

#define TIMEOUT_S            1                 /* Timeout for device response in sec */


/*********************************** DATA TYPES ************************************/

/* Input cmd header */
struct cmd_header {
	uint16_t cmd;       /* 2 bytes - command opcode */
	uint16_t flags;     /* 2 bytes - command flags */
	uint32_t key_id;    /* 4 bytes - key ID to use for crypto functions */
	uint16_t key_size;  /* 2 bytes - key size for KMS commands */
	uint32_t key_cryptoperiod; /* 4 bytes - cryptoperiod to be assigned when creating a new key */
	uint16_t length;    /* 2 bytes - data payload length in bytes */
};                                           


/* Output channel file content format */
struct out_header {
	uint16_t err_code ; /* 2 bytes - error code returned to host */
	uint16_t length;    /* 2 bytes - output payload length in bytes */
};


/* Declaration of output error codes */
typedef enum {
	OUT_ERR_EMPTY = 0,  /* Output header is empty, no error code written (response in output channel not sent) */
	OUT_ERR_NOERR = 1,  /* Cmd concluded correctly payload is meaningful for expected function */
	OUT_ERR_ERROR = 2   /* Cmd concluded with errors, payload not valid for intended operation, but contains error info string */
} out_err_code_t;


/****************************** FUNCTIONS PROTOTYPES *******************************/

/* Prototypes of functions for the interface towards the Device*/
int send_command(uint8_t device_id, struct cmd_header header_buf_in, uint8_t *payload);
int check_output(uint8_t device_id, struct out_header *header_buf_out_p, uint8_t *response);
int reset_choutfile(uint8_t device_id);

#endif /* __com_channel_H */
