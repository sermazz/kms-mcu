#ifndef __rng_custom_H
#define __rng_custom_H

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

/* ARM Semihosting file used as randomness source */
#define RNGFILE_NAME     "/dev/urandom\0"  /* Randomness source file name */
#define RNGFILE_NAME_LEN 13                /* Length of file name string, including \0 */


/****************************** FUNCTIONS PROTOTYPES *******************************/

/* ARM Semihosting interface functions (low-level driver) */
int open_rngfile(int open_mode);
int read_rngfile(int file_handle, void *buf, ssize_t buf_lenght);
int close_rngfile(int file_handle);

/* High-level interface towards RNG */
int init_rng();
int rng_get_random32(uint32_t* random32);

#endif /* __rng_custom_H */
