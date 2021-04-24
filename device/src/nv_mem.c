#include <stdio.h>
#include <stdint.h>
// For trace_printf
#include "diag/Trace.h"
// For ARM Semihosting
#include "arm/semihosting.h"
// My libraries
#include <nv_mem.h>

/*
 * NON-VOLATILE MEMORY LIBRARY
 * ---------------------------
 * Implementation of the library defined in nv_mem.h
 *
 * ARM Semihosting documentation:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0471g/Bgbjjgij.html
 */


/************************************* DEFINES *************************************/

#define __VERBOSE  /* Enable verbose trace_printf NV memory interface errors*/


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* ------------------------------------------------------------------------------- */
/* --------------- ARM Semihosting interface functions prototypes ---------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function open_nvmfile
 * ---------------------
 * Open non-volatile memory file in mode open_mode, defined as
 *               Mode =  0   1   2   3   4   5   6   7   8   9   10   11
 *   ISO C fopen mode =  r   rb  r+  r+b w   wb  w+  w+b a   ab  a+   a+b
 *
 * It returns: a nonzero handler if successful, otherwise -1.
 */
int open_nvmfile(int open_mode)
{
	char file_name[NVMFILE_NAME_LEN] = NVMFILE_NAME;

	void *block[3];
	int ret = 0;
	block[0] = file_name;
	block[1] = (void*)(open_mode);
	block[2] = (void*) NVMFILE_NAME_LEN;

	ret = call_host (SEMIHOSTING_SYS_OPEN, (void*) block);
	return ret;
}

/*
 * Function write_nvmfile
 * ----------------------
 * Write in memory file buf_length bytes taken from device memory location pointed by
 * buf. Note that data type of pointer to input buffer is void * (generic memory
 * which is not allocated to a particular data type), so you have to cast the type of
 * the input to (void *).
 * It returns: -1 in case of errors, otherwise the number of bytes written to file.
 */
int write_nvmfile(int file_handle, void *buf, ssize_t buf_length)
{
	int ret = -1;
	void *block[3];
	block[0] = (void*) file_handle;
	block[1] = (void*) buf;
	block[2] = (void*) buf_length;
	// send character array
	ret = call_host (SEMIHOSTING_SYS_WRITE, (void*) block);
	// this call returns the number of bytes NOT written (0 if all ok)

	// -1 is not a legal value, but SEGGER seems to return it
	if (ret == -1)
		return -1;

	// Return error
	if (ret == (int) buf_length)
		return -1;

	// Return the number of bytes written
	return (ssize_t) (buf_length) - (ssize_t) ret;
}

/*
 * Function read_nvmfile
 * --------------------
 * Read buf_length bytes from memory file and write in device memory location pointed
 * by bug. Note that data type of pointer to output buffer is void *, so you have to
 * cast the type of the input to (void *).
 * It returns: -1 in case of errors, otherwise the number of bytes read from file.
 */
int read_nvmfile(int file_handle, void *buf, ssize_t buf_length)
{
	int ret = -1;
	void *block[3];
	block[0] = (void*) file_handle;
	block[1] = (void*) buf;
	block[2] = (void*) buf_length;
	ret = call_host(SEMIHOSTING_SYS_READ, (void*) block);
	//this call returns the number of bytes NOT written (0 if all ok)
	if (ret == -1){
		return -1;
	}
	if (ret == (int) buf_length){
		return -1;
	}
	return (ssize_t) (buf_length) - (ssize_t) ret;
}

/*
 * Function seek_nvmfile
 * --------------------
 * Seeks to a specified position in the memory file using an offset specified from
 * the start of the file. The file is assumed to be a byte array and the offset is
 * given in bytes.
 * It returns: 0 in case of success, a negative value otherwise.
 */
int seek_nvmfile(int file_handle, int seek_position){
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
 * Function close_nvmfile
 * ---------------------
 * Close the file.
 * It returns: 0 in case of success, -1 otherwise.
 */
int close_nvmfile(int file_handle){
	void *block[1];
	int ret = -1;
	block[0] = (void*) file_handle;
	ret = call_host(SEMIHOSTING_SYS_CLOSE, (void*) block);
	return ret;
}


/* ------------------------------------------------------------------------------- */
/* ----------------- High-level interface towards Flash memory ------------------- */
/* ------------------------------------------------------------------------------- */

/*
 * Function init_nvm
 * -----------------
 * Initialize non-volatile Flash memory.
 * It returns: a number equal to 0 or greater in case of success, -1 otherwise.
 *             Return NVM_NO_FIRST_INIT = 0 -> the NV memory was already initialized
 *             Return NVM_FIRST_INIT = 1 -> the NV memory file was not present, it
 *                                          has now been created and it is empty
 *             Such return value logic is useful when some other component needs to
 *             know when the system is being boot up for the very first time, so that
 *             some other specific registers in the memory may need to be reset to 0
 *             when the non-volatile memory has just been created and is empty.
 *             To facilitate this mechanism a custom return type nvm_init_t is used.
 */
nvm_init_t init_nvm(){
	int file_handle;
	int ret;

	nvm_init_t init_ret = NVM_NO_FIRST_INIT;

	/*
	 * Check whether non-volatile Flash memory file exists: if so, do nothing, else
	 * create it.
	 */

	//Open nv_mem in r+b mode
	file_handle = open_nvmfile(3);
	// If nv_mem file does not exist
	if (file_handle <= 0){
		//Open nv_mem in wb mode (i.e. create it)
		file_handle = open_nvmfile(5);
		if (file_handle <= 0){
			#ifdef __VERBOSE
			trace_printf("ERROR: (nv_mem - 1.1) Error @ open_nvmfile in init_nvm.\n");
			#endif
			return NVM_INIT_ERROR;
		}
		init_ret = NVM_FIRST_INIT;
	}
	//Close
	ret = close_nvmfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 1.2) Error @ close_nvmfile in init_nvm.\n");
		#endif
		return NVM_INIT_ERROR;
	}
	return init_ret;
}

/*
 * Function read_nvm
 * -----------------
 * Read the number of bytes specified by file_size from non-volatile memory, starting
 * from the byte specified by input address; the bytes read are written in the array
 * pointed by file_p.
 * It returns: 0 in case of success, -1 otherwise.
 */
int read_nvm(nvm_address_t address, void *file_p, uint32_t file_size){
	int file_handle;
	int ret;

	//Check if base address + limit is not greater than memory size
	//i.e. if memory access will not overflow memory size
	if (address + file_size > NVM_SIZE){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 2.1) Error @ \"address + file_size > NVM_SIZE\" in read_nvm.\n");
		#endif
		return -1;
	}

	//Open nv_mem in r+b mode (not to truncate memory)
	file_handle = open_nvmfile(3);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 2.2) Error @ open_nvmfile in read_nvm.\n");
		#endif
		return -1;
	}
	//Seek to byte indicated by address
	ret = seek_nvmfile(file_handle, address);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 2.3) Error @ seek_nvmfile in read_nvm.\n");
		#endif
		return -1;
	}
	//Read file_size bytes and store in file_p
	ret = read_nvmfile(file_handle, file_p, file_size);
	if (ret != (int)file_size){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 2.4) Error (ret = %d != file_size = %d, address == %d) @ read_nvmfile in read_nvm.\n", ret, file_size, address);
		#endif
		return -1;
	}
	//Close
	ret = close_nvmfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 2.5) Error @ close_nvmfile in read_nvm.\n");
		#endif
		return -1;
	}
	return 0;
}

/*
 * Function write_nvm
 * ------------------
 * Write the content of the array pointed by file_p to non-volatile memory, starting
 * from the byte specified by input address and for a total number of byte given by
 * file_size.
 * It returns: 0 in case of success, -1 otherwise.
 */
int write_nvm(nvm_address_t address, void *file_p, uint32_t file_size){
	int file_handle;
	int ret;

	//Check if base address + limit is not greater than memory size
	//i.e. if memory access will not overflow memory size
	if (address + file_size > NVM_SIZE){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 3.1) Error @ \"address + file_size > NVM_SIZE\" in write_nvm.\n");
		#endif
		return -1;
	}

	//Open nv_mem in r+b mode (not to truncate memory)
	file_handle = open_nvmfile(3);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 3.2) Error @ open_nvmfile in write_nvm.\n");
		#endif
		return -1;
	}
	//Seek to byte indicated by address
	ret = seek_nvmfile(file_handle, address);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 3.3) Error @ seek_nvmfile in write_nvm.\n");
		#endif
		return -1;
	}
	//Read file_size bytes and store in file_p
	ret = write_nvmfile(file_handle, file_p, file_size);
	if (ret != (int)file_size){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 3.4) Error @ write_nvmfile in write_nvm.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_nvmfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (nv_mem - 3.5) Error @ close_nvmfile in write_nvm.\n");
		#endif
		return -1;
	}
	return 0;
}
