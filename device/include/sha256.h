#ifndef __sha256_H
#define __sha256_H

// FIXME: LITTLE_ENDIAN is already defined in the following file:
// arm-none-eabi/include/machine/endian.h
// which however doesn't seem to be found when compiling. Ideas?
// Who do you want to simulate?
// Intel => LITTLE_END 1
// ARM => LITTLE_END 0
#define LITTLE_END 0

#define ROUND_CONSTANTS_ARRAY_LENGTH 64
#define HASH_CONSTANTS_ARRAY_LENGTH 8
#define NUM_ENTRIES 64

// TODO: Also defined in com_channel.h as PAYLOAD_BUF_IN_SIZE, should I include it directly?
// The payload received is max 7600 Bytes, which is however sent to the HMAC_SHA256 module before,
// not directly to this SAH256 module. This means the SHA256 need to accept a message which is longer
// than 7600 Bytes, since HMAC appends key and message before hashing them (hence the length will be greater
// than 7600)
// Therefore, considered the steps applied by HMAC, the message sent to SHA256 will be long up to 7664 Bytes
#define MAX_MSG_LENGTH_BYTES 7664
#define BLOCK_LENGTH_BITS 512
#define BLOCK_LENGTH_BYTES (BLOCK_LENGTH_BITS >> 3)

// TODO: 7664 Bytes is not a multiple of 64 Bytes (corresponding to 512bits).
// For now, I'm hardcoding the maximum number of blocks available to 7664/64 = 119.75 => 120
// The best solution will be to have 7680 Bytes for the payload/message received by the HMAC function,
//  so that we need a maximum of (7680 + 64) / 64 = 121 blocks of 512bits.
// FIXME: We should always add 1 additional block (used for extreme padding situations like test #3). Hence MAX_NUM_BLOCKS should be computed as follow: MAX_MSG_LENGTH_BYTES / BLOCK_LENGTH_BYTES + 1
#define MAX_NUM_BLOCKS 121
// When expressing the message length during the padding operation, that length is encoded
// using a 64bits long word.
#define MSG_LENGTH_NUMBER_BITS 64

/**
 * @brief Support data structure
 * 
 */
typedef struct data sha256_data_t;
struct data
{
    uint8_t msg[MAX_NUM_BLOCKS * BLOCK_LENGTH_BYTES]; // Original message
    // uint8_t *msg;
    uint16_t L_bytes; // Original message length (bytes) (60800bits maximum, 7600Bytes)
    // uint8_t *padded_msg; // Padded message, ready to be partitioned
    uint16_t L_padded_bytes; // Length of the padded message (after the padding procedure, it must be a multiple of 64Bytes)
    uint16_t left_bits;
    uint8_t num_blocks_occupied; // How many 512bits blocks I was able to fill?
    uint8_t hash[(BLOCK_LENGTH_BYTES >> 1)];
    uint8_t hash_string[BLOCK_LENGTH_BYTES];
};

// A single 512Block is filled into 64 32-bits entries
typedef union entry entry_t;
union entry {
    // A chunk of the message that fits entirely in a 512-bit block
    uint8_t block[BLOCK_LENGTH_BYTES];
    // The 512-bit block partitioned into 16 entries, the remaining 48 will be used for the block expansion
    uint32_t w[NUM_ENTRIES];
};

// sha256.c
// uint8_t sha256sum(uint8_t *msg, uint16_t L_bytes, uint8_t *sha256_hash);
uint8_t sha256sum(sha256_data_t *ptr_data);
int msg_padding(sha256_data_t **ptr_data);
int block_partitioning(sha256_data_t *data, entry_t *block_entry);
void block_extension();
void compression();

// UTILITIES
void vect_swap_endianness(uint8_t *vect_ptr, uint16_t len, uint16_t starting_offset);
uint32_t uint32_t_swap_endianness(uint32_t num);
void append_length_number(sha256_data_t **ptr_data);
uint32_t uint32_t_right_rotate(uint32_t num, uint8_t rot_amount);
void hash_to_string(char *string, uint8_t *digest);

#endif //__sha256_H
