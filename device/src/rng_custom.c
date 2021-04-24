#include <stdio.h>
// For trace_printf
#include "diag/Trace.h"
// For ARM Semihosting
#include "arm/semihosting.h"
// My libraries
#include <rng_custom.h>

/**
 * CUSTOM RANDOM NUMBER GENERATOR DRIVER
 * -------------------------------------
 * This library implements the interface towards a custom random number generator,
 * alternative to the default one provided along with the system.
 * This library is composed of a low-level driver, which actually interfaces with the
 * actual source of randomness, and an high-level interface, which behaves like an
 * API which can be easily called by an application needing some form of random data.
 * Such high-level API wraps the low-level driver functions.
 *
 * The physical random number generator currently employed by this library is the
 * file /dev/urandom; the low-level driver consists of some functions to open and
 * read the file based on ARM Semihosting functionalities.
 *
 * ARM Semihosting documentation:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0471g/Bgbjjgij.html
 */

/************************************* DEFINES *************************************/

#define __VERBOSE  /* Enable verbose trace_printf RNG interface errors*/


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* ------------------------------------------------------------------------------- */
/* ----------------- ARM Semihosting low-level driver functions ------------------ */
/* ------------------------------------------------------------------------------- */

/**
 * Function open_rngfile
 * ---------------------
 * Open randomness source file in mode open_mode, defined as
 *               Mode =  0   1   2   3   4   5   6   7   8   9   10   11
 *   ISO C fopen mode =  r   rb  r+  r+b w   wb  w+  w+b a   ab  a+   a+b
 *
 * It returns: a nonzero handler if successful, otherwise -1.
 */
int open_rngfile(int open_mode)
{
	char file_name[RNGFILE_NAME_LEN] = RNGFILE_NAME;

	void *block[3];
	int ret = 0;
	block[0] = file_name;
	block[1] = (void*)(open_mode);
	block[2] = (void*) RNGFILE_NAME_LEN;

	ret = call_host (SEMIHOSTING_SYS_OPEN, (void*) block);
	return ret;
}

/**
 * Function read_rngfile
 * ---------------------
 * Read buf_lenght bytes from randomness source file and write in device memory
 * location pointed by buf. Note that data type of pointer to output buffer is void *
 * so you have to cast the type of the input to (void *).
 * It returns: -1 in case of errors, otherwise the number of bytes read from file.
 */
int read_rngfile(int file_handle, void *buf, ssize_t buf_lenght)
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

/**
 * Function close_rngfile
 * ----------------------
 * Close the file.
 * It returns: 0 in case of success, -1 otherwise.
 */
int close_rngfile(int file_handle){
	void *block[1];
	int ret = -1;
	block[0] = (void*) file_handle;
	ret = call_host(SEMIHOSTING_SYS_CLOSE, (void*) block);
	return ret;
}


/* ------------------------------------------------------------------------------- */
/* ---------------------- High-level interface towards RNG ----------------------- */
/* ------------------------------------------------------------------------------- */

/**
 * Function init_rng
 * -----------------
 * Initialize random number generator: just open and close the file to check that it
 * exists and can be used (e.g. it will return an error if we are not in a Linux
 * environment and the /dev/urandom file does not exists).
 * It returns: 0  \in case of success, -1 otherwise.
 */
int init_rng(){
	int file_handle;
	int ret;

	//Open RNG file in rb mode
	file_handle = open_rngfile(1);
	if (file_handle <= 0){
		// If RNG file does not exist
		#ifdef __VERBOSE
		trace_printf("ERROR: (rng_custom - 1.1) Error @ open_rngfile in init_rng.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_rngfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (rng_custom - 1.2) Error @ close_rngfile in init_rng.\n");
		#endif
		return -1;
	}
	return 0;
}

/**
 * Function rng_get_random32
 * -------------------------
 * Read 32 bits (4 bytes) from the random number generator managed by the low-level
 * drivers and write them into the uint32_t variable pointed by random32.
 * It returns: 0 in case of success, -1 otherwise.
 */
int rng_get_random32(uint32_t* random32){
	int file_handle;
	int ret;

	//Open RNG file in rb mode
	file_handle = open_rngfile(1);
	if (file_handle <= 0){
		#ifdef __VERBOSE
		trace_printf("ERROR: (rng_custom - 2.1) Error @ open_rngfile in rng_get_random32.\n");
		#endif
		return -1;
	}
	//Read 8 bytes and store in random32
	ret = read_rngfile(file_handle, (void*)random32, sizeof(uint32_t));
	if (ret != (int)sizeof(uint32_t)){
		#ifdef __VERBOSE
		trace_printf("ERROR: (rng_custom - 2.2) Error @ read_rngfile in rng_get_random32.\n");
		#endif
		return -1;
	}
	//Close
	ret = close_rngfile(file_handle);
	if(ret){
		#ifdef __VERBOSE
		trace_printf("ERROR: (rng_custom - 2.3) Error @ close_rngfile in rng_get_random32.\n");
		#endif
		return -1;
	}
	return 0;
}
