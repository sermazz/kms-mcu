/**
 * @file sha256.c
 * @brief 
 * @version 0.1
 * @date 2020-05-15
 * 
 * @copyright Copyright (c) 2020
 * This work is an implementation of the official documentation, which can be found here ->
 * https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
 */

#define __TEST_MODE 0

#include <stdio.h>
#include <string.h>
#include "../include/sha256.h"

#if __TEST_MODE
#include "../../test/sha256_test.h"
#endif

// #define PAYLOAD_BUF_IN_SIZE  7600 // Max 7600 bytes of input cmd payload (defined in com_channel.h)
/* The code handles the creation of a digest over the entire message received, this means that the partitioning 
into 512bits block is handled internally and it's completely transparent to the application requesting the hashing service */

// --- DATA --- //

// Round constant definition
const uint32_t k[ROUND_CONSTANTS_ARRAY_LENGTH] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

union last_padding_u
{
    uint64_t len;
    uint8_t vect[8];
} pad;

/*
int main(int argc, uint8_t const *argv[]);

int main(int argc, uint8_t const *argv[])
{

    return 0;
}
*/

/**
 * @brief Computes the SHA256 digest of the input message
 * 
 * @param msg --> Input message, array of characters (NOT a string)
 * @param L_bytes --> Length of the input message, no string terminator is included
 * @return int (0 --> OK | 1 --> ERROR)
 */
// uint8_t sha256sum(uint8_t *msg, uint16_t L_bytes, uint8_t *sha256_hash)
uint8_t sha256sum(sha256_data_t *ptr_data)
{

    if (ptr_data->L_bytes > MAX_MSG_LENGTH_BYTES)
    {
        // ERROR, Raise Exception
        return 1;
    }

    // sha256_data_t sha256_data;
    entry_t block_entry;

    uint32_t work_vars[HASH_CONSTANTS_ARRAY_LENGTH];
    uint32_t s0_expansion, s1_expansion, s0_compression, s1_compression, ch_compression, tpm1_compression, maj_compression, tmp2_compression;

    // Initial Hash state constants
    uint32_t h[HASH_CONSTANTS_ARRAY_LENGTH] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    ptr_data->L_padded_bytes = ptr_data->L_bytes;
    ptr_data->left_bits = 0;
    ptr_data->num_blocks_occupied = 0;

    if (msg_padding(&ptr_data))
    {
        // Error!!
        return 1;
    }

    // Main "ROUNDS" Loop
    for (uint8_t i = 0; i < ptr_data->num_blocks_occupied; i++)
    {
        memcpy(block_entry.block, &(ptr_data->msg[i * BLOCK_LENGTH_BYTES]), BLOCK_LENGTH_BYTES);

#if LITTLE_END
        // Nothing to do
#else /* ARM */
        for (uint8_t j = 0; j < BLOCK_LENGTH_BYTES; j++)
        {
            block_entry.w[j] = uint32_t_swap_endianness(block_entry.w[j]);
        }
#endif

        /* --> Block Extension <-- */
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        // for i from 16 to 63
        //     s0_expansion := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
        //     s1_expansion := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
        //     w[i] := w[i-16] + s0_expansion + w[i-7] + s1_expansion
        for (uint8_t j = 16; j < BLOCK_LENGTH_BYTES; j++)
        {
            s0_expansion = (uint32_t_right_rotate(block_entry.w[j - 15], 7)) ^ (uint32_t_right_rotate(block_entry.w[j - 15], 18)) ^ (block_entry.w[j - 15] >> 3);
            s1_expansion = (uint32_t_right_rotate(block_entry.w[j - 2], 17)) ^ (uint32_t_right_rotate(block_entry.w[j - 2], 19)) ^ (block_entry.w[j - 2] >> 10);
            block_entry.w[j] = block_entry.w[j - 16] + s0_expansion + block_entry.w[j - 7] + s1_expansion;
        }

        // Initialize working variables to current hash value:
        for (uint8_t j = 0; j < HASH_CONSTANTS_ARRAY_LENGTH; j++)
        {
            work_vars[j] = h[j];
        }

        /* --> Compression <-- */
        // for i from 0 to 63
        // s1_compression := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        // ch := (e and f) xor ((not e) and g)
        // temp1 := h + s1_compression + ch + k[i] + w[i]
        // s0_compression := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        // maj := (a and b) xor (a and c) xor (b and c)
        // temp2:= s0_compression + maj
        for (uint8_t j = 0; j < NUM_ENTRIES; j++)
        {
            s1_compression = (uint32_t_right_rotate(work_vars[4], 6)) ^ (uint32_t_right_rotate(work_vars[4], 11)) ^ (uint32_t_right_rotate(work_vars[4], 25));
            ch_compression = (work_vars[4] & work_vars[5]) ^ (~(work_vars[4]) & work_vars[6]);
            tpm1_compression = work_vars[7] + s1_compression + ch_compression + k[j] + block_entry.w[j];
            s0_compression = (uint32_t_right_rotate(work_vars[0], 2)) ^ (uint32_t_right_rotate(work_vars[0], 13)) ^ (uint32_t_right_rotate(work_vars[0], 22));
            maj_compression = (work_vars[0] & work_vars[1]) ^ (work_vars[0] & work_vars[2]) ^ (work_vars[1] & work_vars[2]);
            tmp2_compression = s0_compression + maj_compression;

            work_vars[7] = work_vars[6];
            work_vars[6] = work_vars[5];
            work_vars[5] = work_vars[4];
            work_vars[4] = work_vars[3] + tpm1_compression;
            work_vars[3] = work_vars[2];
            work_vars[2] = work_vars[1];
            work_vars[1] = work_vars[0];
            work_vars[0] = tpm1_compression + tmp2_compression;
        }
        /* --> Add the compressed chunk to the current hash value <-- */
        for (uint8_t j = 0; j < HASH_CONSTANTS_ARRAY_LENGTH; j++)
        {
            h[j] += work_vars[j];
        }
    } /* End ROUNDS loop */

    /* Produce the Final Hash (Big-Endian) */
    for (uint8_t i = 0, j = 0; i < 8; i++)
    {
        ptr_data->hash[j++] = (uint8_t)(h[i] >> 24);
        ptr_data->hash[j++] = (uint8_t)(h[i] >> 16);
        ptr_data->hash[j++] = (uint8_t)(h[i] >> 8);
        ptr_data->hash[j++] = (uint8_t)h[i];
    }

    hash_to_string((char *)ptr_data->hash_string, ptr_data->hash);

#if __TEST_MODE
    // Let's check if the computed hash matches the expected one
    assert_digest_string(digest_string);
#endif
    // If here, everythig is ok
    return 0;
}

/**
 * @brief 
 * 
 * @param data --> Support data structure
 * @param block_entry --> Used to partition the padded message into 16 32-bits words, for the Block Expansion
 * @return int (0 --> OK | 1 --> ERROR)
 */
int msg_padding(sha256_data_t **ptr_data)
{
    uint16_t tmp_bytes;

    // Let's check how many 512-bit blocks are necessary
    if ((*ptr_data)->L_bytes > BLOCK_LENGTH_BYTES)
    {
        tmp_bytes = (*ptr_data)->L_bytes;
        while (tmp_bytes >= BLOCK_LENGTH_BYTES)
        {
            tmp_bytes -= BLOCK_LENGTH_BYTES;
            (*ptr_data)->num_blocks_occupied++;
        }
        if (!tmp_bytes)
        {
            // The message has filled completely the last 512-bits block
            // We need to instantiate a new block
            (*ptr_data)->left_bits = 0;
        }
        else
        {
            // How many bits are left to complete the block
            (*ptr_data)->left_bits = ((BLOCK_LENGTH_BYTES - tmp_bytes) << 3);
            (*ptr_data)->num_blocks_occupied++;
        }
    }
    else
    {
        (*ptr_data)->left_bits = ((BLOCK_LENGTH_BYTES - (*ptr_data)->L_bytes) << 3);
        (*ptr_data)->num_blocks_occupied = 1;
    }

    // Let's copy the original message into the final one, as a start
    // strncpy((*ptr_data)->msg, (*ptr_data)->msg, (*ptr_data)->L_bytes);

#if __TEST_MODE
    // Let's check it the original message length is equal to the expected one
    assert_L_bytes((*ptr_data)->L_bytes);
    // Let's check if the original message is equal to the original expected one
    assert_msg((*ptr_data)->msg);
    // Let's check if the computed hash matches the expected one
    assert_left_bits((*ptr_data)->left_bits);
#endif

    // Let's find if there's enough space left to place our '1' bit
    if ((*ptr_data)->left_bits <= MSG_LENGTH_NUMBER_BITS)
    {
        // There's not enough room for both the '1' bit and the 64-bit long length number
        // I need an additional 512-bit block to place them
        (*ptr_data)->num_blocks_occupied++;
        (*ptr_data)->left_bits += BLOCK_LENGTH_BITS;
    }

    // Let's add the '1' bit
    // TODO: Check endianness of the following statement
    (*ptr_data)->msg[(*ptr_data)->L_padded_bytes++] = 0x80;
    (*ptr_data)->left_bits -= 8;

    // We have added our '1' bit, do we need "k_bits" '0'-valued bits before our 64-bit long length number?
    if ((*ptr_data)->left_bits > MSG_LENGTH_NUMBER_BITS)
    {
        // There's room for BOTH 'k' '0'-valued bits AND the 64-bit long length number
        // Let's add as many "k_bits" as necessary to reach (*ptr_data)->left_bits == MSG_LENGTH_NUMBER_BITS
        while ((*ptr_data)->left_bits > MSG_LENGTH_NUMBER_BITS)
        {
            // Continue adding '0' bits as padding
            (*ptr_data)->msg[(*ptr_data)->L_padded_bytes++] = 0x00;
            (*ptr_data)->left_bits -= 8;
        }
    }

    // Now we only need to add the 64-bit long length number
    append_length_number(&(*ptr_data));

    if ((*ptr_data)->left_bits)
    {
        // Uhh, that's bad, there's an error
        // Once the message padded there's shouldn't be additional bits left to complete the 512-bit block
        return 1;
    }
    else
    {
#if __TEST_MODE
        assert_L_padded_bytes((*ptr_data)->L_padded_bytes);
        // Let's check if the number of 512-bit blocks occupied is correct
        assert_num_blocks((*ptr_data)->num_blocks_occupied);
#endif
        // If here, then everything is ok
        return 0;
    }
}

// --- UTILITIES --- //

void append_length_number(sha256_data_t **ptr_data)
{
    pad.len = (uint64_t)((*ptr_data)->L_bytes << 3);
    memcpy(&(*ptr_data)->msg[(*ptr_data)->L_padded_bytes], pad.vect, 8);
    (*ptr_data)->L_padded_bytes += sizeof(uint64_t);
    (*ptr_data)->left_bits -= MSG_LENGTH_NUMBER_BITS;

#if LITTLE_END
    // Nothing to do
#else /* ARM */
    // Swap MSByte w/ LSByte and so on
    vect_swap_endianness((*ptr_data)->msg, 8, (*ptr_data)->L_padded_bytes - 8);
#endif
}

void vect_swap_endianness(uint8_t *vect_ptr, uint16_t len, uint16_t starting_offset)
{
    uint8_t tmp;
    uint16_t right_edge = starting_offset + len - 1;
    for (uint8_t i = 0; i < (len >> 1); i++)
    {
        tmp = vect_ptr[i + starting_offset];
        vect_ptr[i + starting_offset] = vect_ptr[right_edge - i];
        vect_ptr[right_edge - i] = tmp;
    }
}

uint32_t uint32_t_swap_endianness(uint32_t num)
{
    num = ((num & 0xFF000000) >> 24) | // move byte 3 to byte 0
          ((num & 0x00FF0000) >> 8) |  // move byte 1 to byte 2
          ((num & 0x0000FF00) << 8) |  // move byte 2 to byte 1
          (num << 24);                 // byte 0 to byte 3
    return num;
}

uint32_t uint32_t_right_rotate(uint32_t num, uint8_t rot_amount)
{
    return num >> rot_amount | num << (32 - rot_amount);
}

void hash_to_string(char *string, uint8_t *digest)
{
    for (uint8_t i = 0; i < 32; i++)
    {
        string += sprintf(string, "%02x", digest[i]);
    }
}
