/**
 *  \file se3_core.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Main Core
 */
#pragma once


#include <se3c0def.h>
#include "stm32f4xx_hal.h"

#if defined(_MSC_VER)
#define SE3_ALIGN_16 __declspec(align(0x10))
#elif defined(__GNUC__)
#define SE3_ALIGN_16 __attribute__((aligned(0x10)))
#else
#define SE3_ALIGN_16
#endif



/** \brief Initialise the device modules
 *
 * Initialise the main cores and data structures
 */
void device_init();


/** \brief Endless loop that executes the commands
 *
 * 	This function stays in idle waiting for command and data transfer requests
 */
void device_loop();

