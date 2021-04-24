#ifndef __TIME_HANDLER_H
#define __TIME_HANDLER_H

/**
 * @file time_handler.h
 * @brief This library acts as an intermediate (and modifiable) layer to easily
 * handle time functionalities expressed using the UNIX epoch standard.
 *
 * In our case, being the device only emulated, the back-end functionality is
 * (for now) provided by the ARM Semihosting library. This library wraps the
 * calls to the ARM Semihosting functions and is intended to be modified in case
 * a new back-end has to be adopted (swapping Semihosting to a more device-aware
 * approach, for example).
 *
 * @version 0.1
 * @date 2020-04-08
 *
 * @copyright Copyright (c) 2020
 */

uint32_t get_time();

#endif