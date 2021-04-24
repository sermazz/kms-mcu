#ifndef __hmac_sha256_H
#define __hmac_sha256_H

#include "sha256.h"

#define IPAD 0x36
#define OPAD 0x5c

#define HASH_OUTPUT_LEN 32

// NOTES from https://tools.ietf.org/html/rfc2104
// B = Hash algorithm compression blocks byte length (512-bits = 64 Bytes in case of SHA256)
// L = hash output length (32 Bytes in case of SHA256)
// The authentication key K can be of any length up to B, the block length of the hash function.
typedef struct hmac_data hmac_data_t;
struct hmac_data
{
    // The original message
    uint8_t msg[MAX_NUM_BLOCKS * BLOCK_LENGTH_BYTES];
    // uint8_t *msg;
    // The original message length, max == MAX_MSG_LENGTH_BYTES
    uint16_t msg_len;

    // The authentication key K can be of any length up to BLOCK_LENGTH_BYTES, the block length of the hash function.
    uint8_t key[MAX_NUM_BLOCKS * BLOCK_LENGTH_BYTES];
    // uint8_t *key;
    // The shared key length, can be of any length up to B (64 Bytes in case of SHA256, i.e. BLOCK_LENGTH_BYTES)
    // Applications that use keys longer than BLOCK_LENGTH_BYTES bytes will first hash the key and then use the resultant L byte digest as the actual key to HMAC. In any case the minimal recommended length for K is L bytes (as the hash output length).
    uint16_t key_len;
    // uint8_t sha256_hash[(BLOCK_LENGTH_BYTES >> 1)];
    uint8_t *hmac_hash;
    uint8_t *hmac_hash_string;
};

uint8_t hmac_sha256(uint8_t *msg, uint16_t msg_len, uint8_t *key, uint16_t key_len, uint8_t *hmac_hash);

#endif // __hmac_sha256_H
