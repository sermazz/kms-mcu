#ifndef __nv_mem_H
#define __nv_mem_H

/*
 * NON-VOLATILE MEMORY LIBRARY
 * ---------------------------
 * This library implements the interface towards the non-volatile memory; due to the
 * device being only emulated, the non-volatile memory is implemented as a binary
 * file on the host machine, and the interface to it is implemented by means of ARM
 * Semihosting mechanism. The file is considered to be of exclusive property of the
 * device, playing the role of an internal physical memory, and thus it is meant to
 * be invisible to the host machine, which should not be able to access it in any way
 *
 * The interface provided by this library has to be substituted by the interface of a
 * physical communication channel with an host in case this software is used for an
 * actually physical device, not an emulated one.
 *
 * For this project, the file managed with ARM Semihosting is just a binary,
 * non-formatted file, whose content is written entirely on a single line and
 * exclusively represent the content of the memory (no string formatting like \n or
 * \t), so that a file seek method can be used to meaningfully address it byte by
 * byte, like an actual memory.
 *
 * ARM Semihosting documentation:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0471g/Bgbjjgij.html
 */


/************************************* DEFINES *************************************/

/* ARM Semihosting non-volatile memory file */
#define NVMFILE_NAME       "./nv_mem\0"  /* Non-volatile memory file name */
#define NVMFILE_NAME_LEN   9             /* Length of NV memory file name string, including \0 */

/* Flash memory characterization */
#define NVM_SIZE           1000000       /* Flash size (in bytes) of STM32F4 = 1 MB */


/*  __  __ ___ __  __  ___  _____   __  __  __   _   ___
 * |  \/  | __|  \/  |/ _ \| _ \ \ / / |  \/  | /_\ | _ \
 * | |\/| | _|| |\/| | (_) |   /\ V /  | |\/| |/ _ \|  _/
 * |_|  |_|___|_|  |_|\___/|_|_\ |_|   |_|  |_/_/ \_\_|
 */

#define KMS_KEYS_NUM_REG_BASE  (nvm_address_t)0  /* Address of register to hold number of keys stored in KMS */
#define KMS_KEYS_NUM_REG_LIMIT 4
#define KMS_DB_BASE            (nvm_address_t)4  /* Base address of the KMS database */
#define KMS_DB_LIMIT           136000


/*********************************** DATA TYPES ************************************/

typedef enum {
	NVM_INIT_ERROR = -1,         /* NV memory initialization error */
	NVM_NO_FIRST_INIT = 0,       /* NV memory was already initialized during a previous boot */
	NVM_FIRST_INIT = 1           /* NV memory initialized for first time (created empty) */
} nvm_init_t;

typedef uint32_t nvm_address_t;  /* 4 byte NV memory address type */


/****************************** FUNCTIONS PROTOTYPES *******************************/

/* ARM Semihosting interface functions prototypes (low-level communication interface) */
int open_nvmfile(int open_mode);
int write_nvmfile(int file_handle, void *buf, ssize_t buf_lenght);
int read_nvmfile(int file_handle, void *buf, ssize_t buf_lenght);
int seek_nvmfile(int file_handle, int seek_position);
int close_nvmfile(int file_handle);

/* High-level interface towards communication channel */
nvm_init_t init_nvm();
int read_nvm(nvm_address_t address, void *file_p, uint32_t file_size);
int write_nvm(nvm_address_t address, void *file_p, uint32_t file_size);

#endif /* __nv_mem_H */
