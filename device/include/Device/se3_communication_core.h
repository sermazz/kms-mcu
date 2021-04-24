/**
 *  \file se3_communication_core.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief USB read/write handlers
 */

#pragma once

#include "se3_common.h"


#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))

/** USB data handlers return values */
enum {
	SE3_PROTO_OK = 0,  ///< Report OK to the USB HAL
	SE3_PROTO_FAIL = 1,  ///< Report FAIL to the USB HAL
	SE3_PROTO_BUSY = 2  ///< Report BUSY to the USB HAL
};

const uint8_t se3_hello[SE3_HELLO_SIZE];

/** \brief USB data receive handler
 *
 *  SEcube API requests are filtered and data is stored in the request buffer.
 *  The function also takes care of the initialization of the special protocol file.
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);

/** \brief USB data send handler
 *
 *  SEcube API requests are filtered and data is sent from the response buffer
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_send(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);



