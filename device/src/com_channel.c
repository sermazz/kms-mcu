#include <stdio.h>

// For trace_printf
#include "diag/Trace.h"
// For ARM Semihosting
#include "arm/semihosting.h"
// My libraries
#include <com_channel.h>
#include <device_cmds.h>


/*
 * COMMUNICATION CHANNEL LIBRARY
 * -----------------------------
 * Implementation of the library defined in com_channel.h (see comments in
 * com_channel.h for further details)
 */


/************************************* DEFINES *************************************/

#define __VERBOSE        /* Enable verbose trace_printf communication errors*/


/************************************ CONSTANTS ************************************/

/* Definition of empty content for header structures of channel_in/out */
const struct cmd_header nop_cmd = {OPCODE_NOP, 0, 0, 0, 0, 0};  /* NOP for input command in channel_in */
const struct out_header no_output = {OUT_ERR_EMPTY, 0};      /* Empty output for channel_out */


/************************************ VARIABLES ************************************/

/*
 * Payloads buffers are statically allocated as global variables, so that dynamic
 * allocation in the stack of each function call is not employed for them. This is
 * due to their size, which is relatively big.
 */

uint8_t payload_buf_in[PAYLOAD_BUF_IN_SIZE];	/* Buffer for input command payload */
uint8_t payload_buf_out[PAYLOAD_BUF_OUT_SIZE];  /* Buffer for output response payload */


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* ------------------------------------------------------------------------------- */
/* --------------- ARM Semihosting interface functions prototypes ---------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function open_chfile
 * --------------------
 * Open channel file in mode open_mode, defined as
 *               Mode =  0   1   2   3   4   5   6   7   8   9   10   11
 *   ISO C fopen mode =  r   rb  r+  r+b w   wb  w+  w+b a   ab  a+   a+b
 *
 * It returns: a nonzero handler if successful, otherwise -1.
 */
int open_chfile(char *file_name, ssize_t file_name_lenght, int open_mode)
{
	void *block[3];
	int ret = 0;
	block[0] = file_name;
	block[1] = (void*)(open_mode);
	block[2] = (void*) file_name_lenght;

	ret = call_host (SEMIHOSTING_SYS_OPEN, (void*) block);
	return ret;
}

/*
 * Function write_chfile
 * ---------------------
 * Write in channel file buf_lenght bytes taken from memory location pointed by buf.
 * Note that data type of pointer to input buffer is void * (generic memory which is
 * not allocated to a particular data type), so you have to cast the type of the
 * input buf to (void *).
 * It returns: -1 in case of errors, otherwise the number of bytes written to file.
 */
int write_chfile(int file_handle, void *buf, ssize_t buf_lenght)
{
	int ret = -1;
	void *block[3];
	block[0] = (void*) file_handle;
	block[1] = (void*) buf;
	block[2] = (void*) buf_lenght;
	// send character array to host file/device
	ret = call_host (SEMIHOSTING_SYS_WRITE, (void*) block);
	// this call returns the number of bytes NOT written (0 if all ok)

	// -1 is not a legal value, but SEGGER seems to return it
	if (ret == -1)
		return -1;

	// The compliant way of returning errors
	if (ret == (int) buf_lenght)
		return -1;

	// Return the number of bytes written
	return (ssize_t) (buf_lenght) - (ssize_t) ret;
}

/*
 * Function read_chfile
 * --------------------
 * Read buf_lenght bytes from channel file and write in memory location pointed by
 * bug. Note that data type of pointer to output buffer is void *, so you have to
 * cast the type of the input to (void *).
 * It returns: -1 in case of errors, otherwise the number of bytes read from file.
 */
int read_chfile(int file_handle, void *buf, ssize_t buf_lenght)
{
	int ret = -1;
	void *block[3];
	block[0] = (void*) file_handle;
	block[1] = (void*) buf;
	block[2] = (void*) buf_lenght;
	ret = call_host(SEMIHOSTING_SYS_READ, (void*) block);
	//this call returns the number of bytes NOT written (0 if all ok)
	if (ret == -1){
		return -1;
	}
	if (ret == (int) buf_lenght){
		return -1;
	}
	return (ssize_t) (buf_lenght) - (ssize_t) ret;
}

/*
 * Function seek_chfile
 * --------------------
 * Seeks to a specified position in a file using an offset specified from the start
 * of the file. The file is assumed to be a byte array and the offset is given in
 * bytes.
 * It returns: 0 in case of success, a negative value otherwise.
 */
int seek_chfile(int file_handle, int seek_position){
	int ret = -1;
	void *block[2];
	block[0] = (void*) file_handle;
	block[1] = (void*) seek_position;
	ret = call_host(SEMIHOSTING_SYS_SEEK, (void*) block);
	if (ret != 0){
		return -1;
	}
	return ret;
}

/*
 * Function close_chfile
 * ---------------------
 * Close the file.
 * It returns: 0 in case of success, -1 otherwise.
 */
int close_chfile(int file_handle){
	void *block[1];
	int ret = -1;
	block[0] = (void*) file_handle;
	ret = call_host(SEMIHOSTING_SYS_CLOSE, (void*) block);
	return ret;
}


/* ------------------------------------------------------------------------------- */
/* ------------- High-level interface towards communication channel -------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function reset_chin
 * -------------------
 * Reset input channel file to an empty header with no payload.
 * It returns: 0 in case of success, -1 otherwise.
 */
int reset_chin(){
	int file_handle;
	int ret;

	//Open channel_in in wb mode
	file_handle = open_chfile(CHFILE_IN_NAME, CHFILE_IN_NAME_LEN, 5);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 1.1) Error @ open_chfile in reset_chin.\n");
		#endif
		return -1;
	}
	//Initialize input channel file to NOP command
	ret = write_chfile(file_handle, (void*)&nop_cmd, sizeof(struct cmd_header));
	if (ret != sizeof(struct cmd_header)){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 1.2) Error @ write_chfile in reset_chin.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_chfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 1.3) Error @ close_chfile in reset_chin.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function read_header_chin
 * -------------------------
 * Read a command header structure from the input channel file and write it into the
 * variable passed by reference with the pointer header_in_p.
 * It returns: 0 in case of success, -1 otherwise.
 */
int read_header_chin(struct cmd_header *header_in_p){
	int file_handle;
	int ret;

	//Open channel_in in rb mode
	file_handle = open_chfile(CHFILE_IN_NAME, CHFILE_IN_NAME_LEN, 1);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 2.1) Error @ open_chfile in read_header_chin.\n");
		#endif
		return -1;
	}
	//Read cmd in the file
	ret = read_chfile(file_handle, (void*)header_in_p, sizeof(struct cmd_header));
	if (ret != sizeof(struct cmd_header)){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 2.2) Error @ read_chfile in read_header_chin.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_chfile(file_handle);
	if (ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 2.3) Error @ close_chfile in read_header_chin.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function read_payload_chin
 * --------------------------
 * Read a payload of the length given by payload_in_len from the input channel file
 * and write it into the internal buffer for input payload, the global variable
 * payload_buf_in.
 * It returns: 0 in case of success, -1 otherwise.
 */
int read_payload_chin(uint16_t payload_in_len){
	int file_handle;
	int ret;

	// Check whether intended payload to read is bigger than buffer
	if (payload_in_len > PAYLOAD_BUF_IN_SIZE){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 3.1) Error @ payload_in_len > PAYLOAD_BUF_IN_SIZE in read_payload_chin.\n");
		#endif
		return -1;
	}

	//Open channel_in in rb
	file_handle = open_chfile(CHFILE_IN_NAME, CHFILE_IN_NAME_LEN, 1);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 3.2) Error @ open_chfile in read_payload_chin.\n");
		#endif
		return -1;
	}
	//Seek to payload position (i.e. end of cmd_header)
	ret = seek_chfile(file_handle, sizeof(struct cmd_header));
	if (ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 3.3) Error @ seek_chfile in read_payload_chin.\n");
		#endif
		return -1;
	}
	//Read cmd payload in channel_in (read payload_in_len bytes, given by cmd_header.length)
	ret = read_chfile(file_handle, (void*)payload_buf_in, payload_in_len);
	if (ret != payload_in_len){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 3.4) Error @ read_chfile in read_payload_chin.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_chfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 3.5) Error @ close_chfile in read_payload_chin.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function reset_chout
 * --------------------
 * Reset output channel file to an empty header with no payload.
 * It returns: 0 in case of success, -1 otherwise.
 */
int reset_chout(){
	int file_handle;
	int ret;

	//Open channel_out in wb mode
	file_handle = open_chfile(CHFILE_OUT_NAME, CHFILE_OUT_NAME_LEN, 5);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 4.1) Error @ open_chfile in reset_chout.\n");
		#endif
		return -1;
	}
	//Write test (empty output)
	ret = write_chfile(file_handle, (void*)&no_output, sizeof(struct out_header));
	if (ret != sizeof(struct out_header)){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 4.2) Error @ write_chfile in reset_chout.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_chfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 4.3) Error @ close_chfile in reset_chout.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function read_header_chout
 * --------------------------
 * Read a command header structure from the output channel file and write it into the
 * variable passed by reference with the pointer header_out_p.
 * It returns: 0 in case of success, -1 otherwise.
 */
int read_header_chout(struct out_header *header_out_p){
	int file_handle;
	int ret;

	//Open channel_out in rb mode
	file_handle = open_chfile(CHFILE_OUT_NAME, CHFILE_OUT_NAME_LEN, 1);
	if (file_handle <= 0)
	{
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 5.1) Error @ open_chfile in read_header_chout.\n");
		#endif
		return -1;
	}
	//Read header
	ret = read_chfile(file_handle, (void*)header_out_p, sizeof(struct out_header));
	if (ret != sizeof(struct out_header))
	{
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 5.2) Error @ read_chfile in read_header_chout.\n");
		#endif
		return -1;
	}
	//Close channel_out
	ret = close_chfile(file_handle);
	if (ret)
	{
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 5.3) Error @ close_chfile in read_header_chout.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function write_header_chout
 * ---------------------------
 * Write the content of a command header structure passed as input header_out to the
 * output channel file.
 * It returns: 0 in case of success, -1 otherwise.
 */
int write_header_chout(struct out_header header_out){
	int file_handle;
	int ret;

	// Check whether output payload is bigger than output buffer size
	if (header_out.length > PAYLOAD_BUF_OUT_SIZE) {
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 6.1) Error @ header_out.length > PAYLOAD_BUF_OUT_SIZE in write_header_chout.\n");
		#endif
		return -1;
	}

	/*
	 * Note that channel_out is opened in r+b mode so that it is not truncated: it
	 * is critical at this step to avoid having a completely empty file, without any
	 * header, because if timeout of host elapses and the file is empty, unexpected
	 * behaviors may occur due to the host not reading neither an EMPTY output header
	 */

	//Open channel_out in wb mode
	file_handle = open_chfile(CHFILE_OUT_NAME, CHFILE_OUT_NAME_LEN, 3);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 6.2) Error @ open_chfile in write_header_chout.\n");
		#endif
		return -1;
	}
	//Write header
	ret = write_chfile(file_handle, (void *)&header_out, sizeof(struct out_header));
	if (ret != sizeof(struct out_header)){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 6.3) Error @ write_chfile in write_header_chout.\n");
		#endif
		return -1;
	}
	//Close channel_out
	ret = close_chfile(file_handle);
	if (ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 6.4) Error @ close_chfile in write_header_chout.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function write_payload_chout
 * ----------------------------
 * Write the content of the internal output buffer payload_buf_out, which should be
 * previously filled with the response to send to the host, to the output channel
 * file channel_out; a number of bytes equal to the input payload_out_len is written.
 * It returns: 0 in case of success, -1 otherwise.
 */
int write_payload_chout(uint16_t payload_out_len){
	int file_handle;
	int ret;

	// Check whether output payload is bigger than output buffer size
	if (payload_out_len > PAYLOAD_BUF_OUT_SIZE) {
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 7.1) Error @ payload_out_len > PAYLOAD_BUF_OUT_SIZE in write_payload_chout.\n");
		#endif
		return -1;
	}

	//Open channel_out in r+b mode, to avoid truncating previously written header
	file_handle = open_chfile(CHFILE_OUT_NAME, CHFILE_OUT_NAME_LEN, 3);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 7.2) Error @ open_chfile in write_payload_chout.\n");
		#endif
		return -1;
	}
	//Seek to payload position (i.e. end of out_header)
	ret = seek_chfile(file_handle, sizeof(struct out_header));
	if (ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 7.3) Error @ seek_chfile in write_payload_chout.\n");
		#endif
		return -1;
	}
	//Write payload
	ret = write_chfile(file_handle, (void*)payload_buf_out, payload_out_len);
	if (ret != payload_out_len){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 7.4) Error @ write_chfile in write_payload_chout.\n");
		#endif
		return -1;
	}
	//Close channel_out
	ret = close_chfile(file_handle);
	if (ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (com_channel - 7.5) Error @ close_chfile in write_payload_chout.\n");
		#endif
		return -1;
	}
	return 0;
}
