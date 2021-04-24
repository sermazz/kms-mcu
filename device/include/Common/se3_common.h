/**
 *  \file se3_common.h
 *  \author Nicola Ferri, Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Common functions and data structures. Debug tools are also here
 */


#pragma once

#include "se3c1def.h"
#include "se3_sdio.h"

extern const uint8_t se3_magic[SE3_MAGIC_SIZE];

#ifndef se3_serial_def
#define se3_serial_def
typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  					///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;
#endif

SE3_SERIAL serial;



const uint8_t debug_string[4];
uint8_t buf_in[124];
uint8_t buf_ciph[124];
uint8_t buf_out[STORAGE_BLK_SIZ];
uint32_t write_addr;
bool command_ready;
