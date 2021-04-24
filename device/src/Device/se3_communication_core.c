

#include "se3_communication_core.h"
#include "stm32f4xx_hal.h"
#ifndef CUBESIM
#include <se3_sdio.h>
#endif

uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
const uint8_t se3_hello[SE3_HELLO_SIZE] = {
		'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
		'c', 'u', 'b', 'e', 0, 0, 0, 0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0
};

enum s3_storage_range_direction {
	range_write, range_read
};

/** \brief SDIO read/write request buffer context */
typedef struct s3_storage_range_ {
	uint8_t* buf;
	uint32_t first;
	uint32_t count;
} s3_storage_range;


/** \brief add request to SDIO read/write buffer
 *  \param range context; the count field must be initialized to zero on first usage
 *  \param lun parameter from USB handler
 *  \param buf pointer to request data
 *  \param block request block index
 *  \param direction read or write
 *  
 *  Contiguous requests are processed with a single call to the SDIO interface, as soon as
 *    a non-contiguous request is added.
 */
static int32_t se3_storage_range_add(s3_storage_range* range, uint8_t lun, uint8_t* buf, uint32_t block, enum s3_storage_range_direction direction)
{
	bool ret = true;
	if (range->count == 0) {
		range->buf = buf;
		range->first = block;
		range->count = 1;
	}
	else {
		if (block == range->first + range->count) {
			range->count++;
		}
		else {
			if (direction == range_write){
				ret = secube_sdio_write(lun, range->buf, range->first, range->count);
				SE3_TRACE(("%i: write buf=%u count=%u to block=%u", ret, (unsigned)range->buf, range->count, range->first));
			}
			else {
				ret = secube_sdio_read(lun, range->buf, range->first, range->count);
				SE3_TRACE(("%d: read buf=%u count=%u from block=%u", ret, (unsigned)range->buf, range->count, range->first));
			}
			range->count = 0;
		}
	}

	return (ret)?(SE3_PROTO_OK):(SE3_PROTO_FAIL);
}


/**	User-written USB interface that implements the write operation of the
 *	driver; it forwards the data on the SD card if the data block does not
 *	 contain the magic sequence, otherwise the data block is unpacked for further
 *	 elaborations;
 */
int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	int32_t r = SE3_PROTO_OK;
	uint32_t block;
	int index;
	const uint8_t* data = buf;
	//uint16_t u16tmp;

	s3_storage_range range = {
			.first = 0,
			.count = 0
	};

	if(memcmp(debug_string, data, 4) == 0 && command_ready == false) {
		memcpy(buf_in, data +4, 124); //skip the initial command string

		write_addr = blk_addr;
		command_ready = true;

		return SE3_PROTO_OK;
	}

	for (block = blk_addr; block < blk_addr + blk_len; block++) {
		r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
		data += SE3_COMM_BLOCK;
	}

	//flush any remaining block
	return se3_storage_range_add(&range, lun, NULL, 0xFFFFFFFF, range_write);
}



/*	User-written USB interface that implements the read operation of the
 * 	driver; it sends the data on the SD card if the data block does not
 *	contain the magic sequence, otherwise it handles the proto request.
 */
int32_t se3_proto_send(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	int32_t r = SE3_PROTO_OK;
	uint32_t block;
	int index;
	uint8_t* data = buf;
	s3_storage_range range = {
			.first = 0,
			.count = 0
	};

	for (block = blk_addr; block < blk_addr + blk_len; block++) {
		if (r == SE3_PROTO_OK) r = se3_storage_range_add(&range, lun, data, block, range_read);
		data += SE3_COMM_BLOCK;
	}

	//flush any remaining block
	if (r == SE3_PROTO_OK) r = se3_storage_range_add(&range, lun, NULL, 0xFFFFFFFF, range_read);
	return r;
}


