#ifndef __com_channel_H
#define __com_channel_H

/*
 * COMMUNICATION CHANNEL LIBRARY
 * -----------------------------
 * This library implements the interface channel between the host machine and the
 * device. It provides two kinds of functions:
 *
 * + high-level functions to directly manage the main communication functions (init
 *   communication, read/write header, read/write payload): these are implementation-
 *   independent and can be easily used by the device main() without knowing anything
 *   about the actually adopted communication channel
 *
 * + low-level functions implementing the interface of such function towards the
 *   actual communication channel: in these library they are implemented by means of
 *   ARM Semihosting mechanism, using two shared binary files; in case a different
 *   communication mean is adopted (e.g. in the case of an actual, non-emulated
 *   device), the are the only one to be modified
 *
 * For this project, a double channel is implemented, employing:
 * - an input channel file for input commands going from Host to Device
 * - an output channel file for communications going from Device to Host
 * Both channel files work as buffers containing only one single input command or
 * output response at a time, which is consumed respectively by the device and the
 * host as soon as it gets read; normally (i.e. when empty) the channel files contain
 * a dummy content (a NOP cmd, for the input channel file, and an EMPTY output, for
 * the output channel file).
 *
 * ARM Semihosting documentation:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0471g/Bgbjjgij.html
 */


/************************************* DEFINES *************************************/

/* ARM Semihosting communication files */
#define CHFILE_IN_NAME       "./channel_in\0"   /* Input Channel file name */
#define CHFILE_OUT_NAME      "./channel_out\0"  /* Output Channel file name */
#define CHFILE_IN_NAME_LEN   13                 /* Length of channel file name string, including \0 */
#define CHFILE_OUT_NAME_LEN  14		            /* Length of channel file name string, including \0 */

/* Payloads buffer limit */
#define PAYLOAD_BUF_IN_SIZE  7600                /* Max 7600 bytes of input cmd payload */
#define PAYLOAD_BUF_OUT_SIZE 7600                /* Max 7600 bytes of output payload */


/*********************************** DATA TYPES ************************************/

/*
 * Input/output payload fields are not included within input and output headers data
 * structures cmd_header and out_header because, otherwise, read_chfile and
 * write_chfile would always access channel_in and channel_out writing/reading the
 * max payload buffer size PAYLOAD_BUF_IN/OUT_SIZE (due to the indication of the size
 * of the access being sizeof(struct cmd_header/out_header), which is not efficient
 * (even if still produces a correct behavior due to the indication of the payload
 * length in LENGTH field of the headers, so that overflow never occurs anyway).
 */

/* Input channel file command format */
/* || 2 byte OPCODE | 2 bytes FLAGS | 4 bytes KEY_ID | 2 byte KEY_SIZE | 2 byte LENGTH | 4 byte CRYPTOPERIOD | N bytes Payload || */
struct cmd_header {
	uint16_t cmd;       /* 2 bytes - command opcode */
	uint16_t flags;     /* 2 bytes - command flags */
	uint32_t key_id;    /* 4 bytes - key ID to use for crypto functions */
	uint16_t key_size;  /* 2 bytes  - key size for KMS commands */
	uint32_t key_cryptoperiod; /* 4 bytes - cryptoperiod to be assigned when creating a new key */
	uint16_t length;    /* 2 bytes - data payload length in bytes */
};

/* Output channel file content format */
/* || 2 bytes ERROR CODE || 2 bytes LENGTH | N bytes Payload || */
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

/* ARM Semihosting interface functions prototypes (low-level communication interface) */
int open_chfile(char *file_name, ssize_t file_name_lenght, int open_mode);
int write_chfile(int file_handle, void *buf, ssize_t buf_lenght);
int read_chfile(int file_handle, void *buf, ssize_t buf_lenght);
int seek_chfile(int file_handle, int seek_position);
int close_chfile(int file_handle);

/* High-level interface towards communication channel */
// input channel
int reset_chin();
int read_header_chin(struct cmd_header *header_in_p);
int read_payload_chin(uint16_t payload_in_len);
// output channel
int reset_chout();
int read_header_chout(struct out_header *header_out_p);
int write_header_chout(struct out_header header_out);
int write_payload_chout(uint16_t payload_out_len);

#endif /* __com_channel_H */
