/**
 * @file hmac_sha256.c
 * @brief HMAC implementation based on SHA256
 * @version 0.1
 * @date 2020-05-23
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#define __TEST_MODE 0

#include <stdio.h>
#include <string.h>
#include "../include/hmac_sha256.h"

#if __TEST_MODE
#include "../../test/hmac_sha256_test.h"
#endif

/*
 * HMAC(H, K) == H(K ^ opad, H(K ^ ipad, text))
 *
 *    H: Hash function (sha256)
 *    K: Secret key
 *    B: Block byte length
 *    L: Byte length of hash function output
 *
 * https://tools.ietf.org/html/rfc2104
 */

// int main(int argc, char const *argv[]);

static uint8_t key_expansion(hmac_data_t *ptr_data);

// --- hmac_data --- //

// int main(int argc, char const *argv[])
// {
//     hmac_sha256("abc", 3, "abc", 3, NULL);
//     return 0;
// }

uint8_t hmac_sha256(uint8_t *msg, uint16_t msg_len, uint8_t *key, uint16_t key_len, uint8_t *hmac_hash)
{
    hmac_data_t hmac_data;
    sha256_data_t sha256_data;

    uint8_t k_IPAD[MAX_MSG_LENGTH_BYTES], k_OPAD[MAX_MSG_LENGTH_BYTES];

    hmac_data.msg_len = msg_len;
    memcpy(hmac_data.msg, msg, hmac_data.msg_len);
    // hmac_data.msg = msg;
    hmac_data.key_len = key_len;
    memcpy(hmac_data.key, key, hmac_data.key_len);
    // hmac_data.key = key;

#if __TEST_MODE
    assert_msg(hmac_data.msg);
    assert_msg_len(hmac_data.msg_len);
    assert_key(hmac_data.key);
    assert_key_len(hmac_data.key_len);
#endif

    // Let's determine if the key length is greater than BLOCK_LENGTH_BYTES
    if (key_len > BLOCK_LENGTH_BYTES)
    {
        // Hash the key and then use the resultant L byte digest as the actual key to HMAC
        sha256_data.L_bytes = hmac_data.key_len;
        memcpy(sha256_data.msg, hmac_data.key, sha256_data.L_bytes);
        if (sha256sum(&sha256_data) == 1)
        {
            // TODO: ERROR, Raise Exception
            return 1;
        }

        // The key in use is now the hash of the original key
        // Its length is the length of a SHA256 hash, i.e. 32 Bytes
        hmac_data.key_len = (BLOCK_LENGTH_BYTES >> 1);
        memcpy(hmac_data.key, sha256_data.hash, hmac_data.key_len);
        // printf("SHA Key: %s\n", sha256_data.hash_string);
    }
    // The key length is smaller than "BLOCK_LENGTH_BYTES", hence we need to expand it to "BLOCK_LENGTH_BYTES"
    // (1) Append zeros to the end of K to create a B byte string
    // (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 zero bytes 0x00)
    if (key_expansion(&hmac_data))
    {
        // TODO: ERROR, Raise Exception
        return 1;
    }

    memcpy(k_IPAD, hmac_data.key, hmac_data.key_len);
    memcpy(k_OPAD, hmac_data.key, hmac_data.key_len);

    // (2) XOR (bitwise exclusive-OR) the "B" byte key computed in step (1) with IPAD
    // (5) XOR (bitwise exclusive-OR) the "B" byte key computed in step (1) with OPAD
    for (uint16_t i = 0; i < hmac_data.key_len; i++)
    {
        // res_xor[i] = hmac_data.key[i] ^ k_IPAD[i];
        k_IPAD[i] ^= IPAD;
        k_OPAD[i] ^= OPAD;
    }

    // (3) Append the stream of hmac_data "msg" to the B byte string resulting from the previous step
    for (uint16_t i = 0; i < hmac_data.msg_len; i++)
    {
        k_IPAD[hmac_data.key_len + i] = hmac_data.msg[i];
    }
    sha256_data.L_bytes = hmac_data.key_len + hmac_data.msg_len;

    // (4) Apply SHA256 to the stream generated in the previous step
    memcpy(sha256_data.msg, k_IPAD, sha256_data.L_bytes);
    if (sha256sum(&sha256_data))
    {
        // TODO: ERROR, Raise Exception
        return 1;
    }

    // (6) append the SHA256 result from step (4) to the B byte key resulting from step (5)
    for (uint8_t i = 0; i < (BLOCK_LENGTH_BYTES >> 1); i++)
    {
        k_OPAD[hmac_data.key_len + i] = sha256_data.hash[i];
    }
    sha256_data.L_bytes = hmac_data.key_len + (BLOCK_LENGTH_BYTES >> 1);

    // (7) apply SHA256 to the stream generated in step (6) and output the result
    memcpy(sha256_data.msg, k_OPAD, sha256_data.L_bytes);
    if (sha256sum(&sha256_data))
    {
        // TODO: ERROR, Raise Exception
        return 1;
    }
    hmac_data.hmac_hash = sha256_data.hash;
    hmac_data.hmac_hash_string = sha256_data.hash_string;

    for(uint8_t i = 0; i < (BLOCK_LENGTH_BYTES >> 1); i++)
    	hmac_hash[i] = hmac_data.hmac_hash[i];


#if __TEST_MODE
    assert_hmac_hash_string(hmac_data.hmac_hash_string);
#endif

    // If here, everything is OK
    return 0;
}

static uint8_t key_expansion(hmac_data_t *ptr_data)
{
    // while (key_len < BLOCK_LENGTH_BYTES)
    for (; ptr_data->key_len < BLOCK_LENGTH_BYTES;)
    {
        ptr_data->key[ptr_data->key_len++] = 0x00;
    }
    return 0;
}
