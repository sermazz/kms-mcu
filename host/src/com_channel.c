#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//System library for delay
#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
// My libraries
#include "com_channel.h"
#include "host_cmds.h"

/*
 * COMMUNICATION CHANNEL LIBRARY
 * -----------------------------
 * Implementation of the library defined in com_channel.h (see comments in
 * com_channel.h for further details)
 */


/************************************* DEFINES *************************************/

//#define __DEBUG        /* Enable verbose debug information */
#define __VERBOSE        /* Enable verbose communication information */
//#define __BREAKPOINTS  /* Enable breakpoints with getchar */

/************************************ CONSTANTS ************************************/
const struct cmd_header nop_cmd = {OPCODE_NOP, 0, 0, 0, 0, 0};  /* NOP for input command for input packet */
const struct out_header no_output = {OUT_ERR_EMPTY, 0};      /* Empty output for output packet */


/****************************** FUNCTIONS DEFINITIONS ******************************/

/*
 * Function send_command
 * ---------------------
 * Send a command to Device: while the device is polling the input channel file, this
 * function accesses it once in write mode to write the given command. The command is
 * specified with its header (struct cmd_header) and payload, passed as pointer to
 * uint8_t array. The length of the payload which must be written in the file is
 * specified in the passed header struct.
 * It returns: 0 if successful, otherwise -1.
 */
int send_command(uint8_t device_id, struct cmd_header header_buf_in, uint8_t *payload)
{
	FILE *file_handle;
	int ret;
	char *chfile_in_name = NULL;
	
	// Set channel file path basing on device index
	// assuming 8-bit device index, at most must append "_255/" = +5 characters; +1 is for NULL
	chfile_in_name = (char*)malloc((strlen(CHFILE_DIR"\0") + 5 + strlen(CHFILE_IN_NAME) + 1) * sizeof(char));
	if (!chfile_in_name)
	{
		#ifdef __VERBOSE
		printf("ERROR: (1.1) Not enough memory to dynamically allocate string.\n");
		#endif
		return -1;
	}
	sprintf(chfile_in_name, CHFILE_DIR"_%hhu/"CHFILE_IN_NAME, device_id); // automatically appends '\0'

	/* Check if input payload size is bigger than buffer size */
	if (header_buf_in.length > PAYLOAD_BUF_IN_SIZE)
	{
		#ifdef __VERBOSE
		printf("ERROR: (1.2) Too big input payload size.\n");
		#endif
		return -1;
	}

	/* 
	 * Open channel_in in r+b mode (instead of wb) so that the file is not truncated
	 * as soon as fopen is launched, and a change is detected by the device poll only
     * after fclose has concluded (critical because device constantly polls input
	 * channel file channel_in); with wb mode, indeed, the file is truncated and made
	 * empty as soon as opened. Data remaining in channel_in after
	 * sizeof(struct cmd_header) bytes do not represent a problem since the device
	 * always knows the exact quantity of bytes to read (size of header + potential
	 * size of payload defined by LENGTH field), so that it does not read old data
	 * permaned from previous communications, or uninitialized data.
	 */
	//Open channel_in in r+b
	file_handle = fopen(chfile_in_name, "r+b");
	if (!file_handle)
	{
		#ifdef __VERBOSE
		printf("ERROR: (1.3) Error in opening input channel file to send command.\n");
		#endif
		return -1;
	}
	//Write command (1 block of sizeof(struct cmd_header) bytes)
	ret = fwrite(&header_buf_in, sizeof(struct cmd_header), 1, file_handle);
	if (ret != 1)
	{
		#ifdef __VERBOSE
		printf("ERROR: (1.4) Error in writing input channel file to send command.\n");
		#endif
		return -1;
	}
	//Write payload if any
	if (header_buf_in.length != 0)
	{
		ret = fwrite(payload, header_buf_in.length, 1, file_handle);
		if (ret != 1)
		{
			#ifdef __VERBOSE
			printf("ERROR: (1.5) Error in writing input channel file to send payload.\n");
			#endif
			return -1;
		}
	}
	//Close (only updates file after closing)
	ret = fclose(file_handle);
	if (ret)
	{
		#ifdef __VERBOSE
		printf("ERROR: (1.6) Error in closing input channel file to send command.\n");
		#endif
		return -1;
	}

	#ifdef __BREAKPOINTS
	/* ------------- BREAKPOINT ------------- */
	printf("Breakpoint 1 - end of send_command\n");
	getchar();
	#endif

	return 0;
}

/*
 * Function check_output
 * ---------------------
 * Wait for timeout and then check if a response arrived from Device; if a response
 * arrived, meaning that an header different from no_output is present in channel_out
 * read the attached output payload, whose size is specified by the LENGTH field of
 * the just read output header.
 * It returns:  0 = if cmd communication concluded successfully
 *             -1 = if not succesful for some hard fault
 */
int check_output(uint8_t device_id, struct out_header *header_buf_out_p, uint8_t *response)
{

	FILE *file_handle;
	int ret;
	char *chfile_out_name = NULL;
	
	// Set channel file path basing on device index
	// assuming 8-bit device index, at most must append "_255/" = +5 characters; +1 is for NULL
	chfile_out_name = (char*)malloc((strlen(CHFILE_DIR"\0") + 5 + strlen(CHFILE_OUT_NAME) + 1) * sizeof(char));
	if (!chfile_out_name)
	{
		#ifdef __VERBOSE
		printf("ERROR: (2.1) Not enough memory to dynamically allocate string.\n");
		#endif
		return -1;
	}
	sprintf(chfile_out_name, CHFILE_DIR"_%hhu/"CHFILE_OUT_NAME, device_id); // automatically appends '\0'
	
	//Delay basing on system
	#if defined(__linux__) || defined(__APPLE__)
	sleep(TIMEOUT_S);
	#elif defined(_WIN32)
	Sleep(TIMEOUT_S * 1000);
	#endif

	#ifdef __DEBUG
	printf("Timeout elapsed, checking device output...\n");
	#endif

	//Open channel_out
	file_handle = fopen(chfile_out_name, "rb");
	if (!file_handle)
	{
		#ifdef __VERBOSE
		printf("ERROR: (2.2) Error in opening output channel file to check response.\n");
		#endif
		return -1;
	}

	/* 
	 * Same mechanism with which the Device reads input channel file: read first the
	 * known fields, which also tell the length of the payload, then read the payload
	 * only reading the specified length, so that you never risk to read
	 * uninitialized data or data remained from previous communications.
	 */

	//Read (1 block of sizeof(struct out_header) bytes)
	ret = fread(header_buf_out_p, sizeof(struct out_header), 1, file_handle);
	if (ret != 1)
	{
		#ifdef __VERBOSE
		printf("ERROR: (2.3) Error in reading output channel file to check response.\n");
		#endif
		#ifdef __DEBUG
		printf("ret = %d\n", ret);
		#endif
		return -1;
	}

	/* 
	 * Normally channel_out contains the EMPTY output, so that the ERR_CODE field is
	 * OUT_ERR_EMPTY and the LENGTH field is 0; as soon as the device writes a 
	 * response in channel_out, the host consumes it, resetting the file back EMPTY
	 * output. THus, if a content of channel_out different from EMPTY output is
	 * detected, then it means a new response arrived.
	 * When a new response arrives, this function first looks to the header to read
	 * the LENGTH field, then it completes the reading operation reading an amount of
	 * additional bytes defined by LENGTH field.
	 */

	//If new response
	if (header_buf_out_p->err_code != no_output.err_code && header_buf_out_p->length != no_output.length)
	{
		//Read payload = 1 block of header_buf_out_p->length bytes
		ret = fread(response, header_buf_out_p->length, 1, file_handle);
		if (ret != 1)
		{
			#ifdef __VERBOSE
			printf("ERROR: (2.4) Error in reading output channel file to gather payload.\n");
			#endif
			#ifdef __DEBUG
			printf("ret = %d | header_buf_out_p->length = %d\n", ret, header_buf_out_p->length);
			#endif
			return -1;
		}
	}

	//Close channel_out
	ret = fclose(file_handle);
	if (ret)
	{
		#ifdef __VERBOSE
		printf("ERROR: (2.5) Error in closing output channel file to gather payload.\n");
		#endif
		return -1;
	}

	#ifdef __BREAKPOINTS
	/* ------------- BREAKPOINT ------------- */
	printf("Breakpoint 2 - end of check_output\n");
	getchar();
	#endif

	return 0;
}

/*
 * Function reset_choutfile
 * ------------------------
 * Reset channel_out file to an EMPTY output content (i.e. consume the response
 * received from the device by setting the output to no_output).
 * It returns: 0 if successful, otherwise -1.
 */
int reset_choutfile(uint8_t device_id)
{
	FILE *file_handle;
	int ret;
	char *chfile_out_name = NULL;
	
	// Set channel file path basing on device index
	// assuming 8-bit device index, at most must append "_255/" = +5 characters; +1 is for NULL
	chfile_out_name = (char*)malloc((strlen(CHFILE_DIR"\0") + 5 + strlen(CHFILE_OUT_NAME) + 1) * sizeof(char));
	if (!chfile_out_name)
	{
		#ifdef __VERBOSE
		printf("ERROR: (3.1) Not enough memory to dynamically allocate string.\n");
		#endif
		return -1;
	}
	sprintf(chfile_out_name, CHFILE_DIR"_%hhu/"CHFILE_OUT_NAME, device_id); // automatically appends '\0'

	//Open channel_out
	file_handle = fopen(chfile_out_name, "wb");
	if (!file_handle)
	{
		#ifdef __VERBOSE
		printf("ERROR: (3.2) Error in opening output channel file to reset it.\n");
		#endif
		return -1;
	}
	//Write no_output (1 block of sizeof(struct out_header) bytes)
	ret = fwrite(&no_output, sizeof(struct out_header), 1, file_handle);
	if (ret != 1)
	{
		#ifdef __VERBOSE
		printf("ERROR: (3.3) Error in writing output channel file to reset it.\n");
		#endif
		return -1;
	}
	//Close
	ret = fclose(file_handle);
	if (ret)
	{
		#ifdef __VERBOSE
		printf("ERROR: (3.4) Error in closing output channel file to reset it.\n");
		#endif
		return -1;
	}

	#ifdef __BREAKPOINTS
	/* ------------- BREAKPOINT ------------- */
	printf("Breakpoint 3 - end of reset_choutfile\n");
	getchar();
	#endif

	return 0;
}