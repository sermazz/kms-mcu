#ifndef __aes256_H
#define __aes256_H

#include <stdio.h>

#define SBOXLEN 256

/* Number of 32-bit words in the State (block size) */
#define Nb 4
/* Key length */
#define Nk 8
/* Number of rounds for AES-256 */
#define Nr 14

/* AES-256 constants in bytes */
#define AES_KEYLEN 32
#define AES_KEYEXPLEN 240

/* Size in bytes of a State block: 4 words of 4 bytes = 16 bytes */
#define AES_BLOCK_SIZE 16

/* State block of 128 bits */
typedef uint8_t state_t[Nb][Nb];

int encrypt_ecb(char *payload, unsigned short len, char *key, char *output);
void decrypt_ecb(char *payload, unsigned short len, char *key, char *output);
int encrypt_cbc(char *payload, unsigned short len, char *key, char *output);
void decrypt_cbc(char *payload, unsigned short len, char *key, char *output);

#endif
