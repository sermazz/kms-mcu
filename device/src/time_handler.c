/**
 * @file time_handler.c
 * @brief This library acts as an intermediate (and modifiable) layer to easily handle time
 * functionalities expressed using the UNIX epoch standard.
 *
 * In our case, being the device only emulated, the back-end functionality is (for now) provided by
 * the ARM Semihosting library. This library wraps the calls to the ARM Semihosting functions and is
 * intended to be modified in case a new back-end has to be adopted (swapping Semihosting to a more
 * device-aware approach, for example).
 *
 * @version 0.1
 * @date 2020-08-04
 *
 * @copyright Copyright (c) 2020
 */

#include "diag/Trace.h"      // For trace_printf
#include "arm/semihosting.h" // For ARM Semihosting

// My libraries
#include <time_handler.h>

// --- DEFINES ---

#define __VERBOSE /* Enable verbose trace_printf NV memory interface errors*/

// --- FUNCTIONS DEFINITIONS ---

/**
 * @brief Get the actual time in UNIX format (i.e. the number of seconds from 01-01-1970).
 *
 * -- ARM Semihosting implementation specific -- If the number returned is 0 there's an error.
 *
 * -- Other implementations -- Modify this functions if other back-ends are used (such as the
 * HAL_RTC driver provided by STMicroelectronics). 
 *
 * +++ IN ANY CASE, THIS FUNCTION MUST RETURN A UINT32_T SPECIFYING THE TIME IN UNIX EPOCH FORMAT
 * +++ An adequate function may be needed to convert and obtain such a value if the back-end doesn't
 * provide itself by default...
 *
 * @return uint32_t specifying the number of seconds in UNIX epoch
 * 0 if error, any other value otherwise
 */
uint32_t get_time()
{
    int actual_time = call_host(SEMIHOSTING_SYS_TIME, (void *)NULL);
    if (actual_time == 0)
    {
#ifdef __VERBOSE
        trace_printf("ERROR: (time_handler - 1.1) Error @ call_host in get_time\n");
#endif
        return 0;
    }
    else
    {
        return actual_time;
    }
}