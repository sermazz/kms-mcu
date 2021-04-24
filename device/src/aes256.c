#include <aes256.h>
#include <stdlib.h>
#include <stdio.h>
#include "diag/Trace.h"

/************************************* DEFINES *************************************/

//#define __DEBUG  /* Enable trace_printf debug information */

/******************************** STATIC PROTOTYPES ********************************/

#ifdef __DEBUG
static void print_state(state_t* state);
#endif
static uint8_t get_sbox(int num);
static uint8_t get_sbox_inv(int num);
static void state_xor(state_t* state,state_t* iv);
static void state_cpy(state_t* iv,state_t* state);
static void sub_bytes(state_t* state);
static void r_sub_bytes(state_t* state);
static void shift_rows(state_t* state);
static void r_shift_row(state_t* state);
static void add_round_key(int round, state_t* state, const uint8_t* round_key);
static uint8_t xtime(uint8_t x);
static void mix_columns(state_t* state);
static uint8_t multiply(uint8_t x, uint8_t y);
static void r_mix_column(state_t* state);
static void key_expansion(uint8_t* round_key, const uint8_t* key);
static void cipher(state_t* state, char *key);
static void matrix_iv(state_t *iv);
static void r_cipher(state_t* state, char *key);


/************************************ CONSTANTS ************************************/

static const state_t iv = {
		{0x00, 0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07},
		{0x08, 0x09, 0x0a, 0x0b},
		{0x0c, 0x0d, 0x0e, 0x0f}
};
 
/* S-box used in sub_bytes() function for encryption */
static const uint8_t sbox[SBOXLEN] = {
  /*        0     1    2      3     4    5     6     7      8    9     a      b    c     d     e     f */
  /* 0 */ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  /* 1 */ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  /* 2 */ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  /* 3 */ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  /* 4 */ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  /* 5 */ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  /* 6 */ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  /* 7 */ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  /* 8 */ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  /* 9 */ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  /* a */ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  /* b */ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  /* c */ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  /* d */ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  /* e */ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  /* f */ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

/* Reverse S-box used for decryption */
  static const uint8_t rsbox[SBOXLEN] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

/* Round constants */
static const uint8_t rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* Functions to get values from sbox */
static uint8_t get_sbox(int num){
  return sbox[num];
}

static uint8_t get_sbox_inv(int num){
  return rsbox[num];
}

#ifdef __DEBUG
/* Debug function to print the state_t type */ 
static void print_state(state_t* state){
  uint8_t i,j;
  for(i=0;i<Nb;i++){
      for(j=0;j<Nb;j++){
          trace_printf("\\x%02x", (unsigned char) (*state)[i][j]); 
      }
      trace_printf("\n");
    }
}
#endif

/* state_xor() performs the XOR operation between the elements of two state_t type */
static void state_xor(state_t* state,state_t* iv){
  uint8_t i,j;
  for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
          (*state)[i][j] ^= (*iv)[i][j];
      }
    }
}
/* state_cpy() performs the copy of a state_t type in a state_t type */
static void state_cpy(state_t* iv,state_t* state){
  uint8_t i,j = 0;
  for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
          (*iv)[i][j] = (*state)[i][j];
      }
    }
}
/* sub_bytes() applies the S-box to each byte of the State. */
static void sub_bytes(state_t* state){
  uint8_t i, j;
  for (j = 0; j < Nb; j++){
    for (i = 0; i < Nb; i++){
      (*state)[i][j] = get_sbox((*state)[i][j]);
    }
  }
}

/* r_sub_bytes() applies the reverse S-box to each byte of the State for decryption. */
static void r_sub_bytes(state_t* state){
  uint8_t i, j;
  for (j = 0; j < Nb; j++){
    for (i = 0; i < Nb; i++){
      (*state)[i][j] = get_sbox_inv((*state)[i][j]);
    }
  }
}

/* shift_rows() cyclically shifts the last three rows in the State */
static void shift_rows(state_t* state){
    uint8_t temp;

  /* Row 0 doesn't shift */
  /* Shift left row 1 by one position */ 
  temp           = (*state)[1][0];
  (*state)[1][0] = (*state)[1][1];
  (*state)[1][1] = (*state)[1][2];
  (*state)[1][2] = (*state)[1][3];
  (*state)[1][3] = temp;

   /* Shift left row 2 by two position */ 
  temp           = (*state)[2][0];
  (*state)[2][0] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[2][1];
  (*state)[2][1] = (*state)[2][3];
  (*state)[2][3] = temp;

  /* Shift left row 3 by three position, actually is one shift right */ 
  temp           = (*state)[3][3];
  (*state)[3][3] = (*state)[3][2];
  (*state)[3][2] = (*state)[3][1];
  (*state)[3][1] = (*state)[3][0];
  (*state)[3][0] = temp;
}

/* reverse function of shift_rows(), basically shift in the opposite way the rows */
static void r_shift_row(state_t* state){
    uint8_t temp;
  /* Row 0 doesn't shift */

  /* Shift right row 1 by one position */
    temp           = (*state)[1][3];
    (*state)[1][3] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][0];
    (*state)[1][0]= temp;

   /* Shift right row 2 by two position */ 
    temp           = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

  /* Shift right row 3 by three position, actually is one shift left */ 
    temp           = (*state)[3][0];
    (*state)[3][0] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][3];
    (*state)[3][3] = temp;
    
}

/* add_round_key() XORs each column of the State with a word from the key schedule. */
static void add_round_key(int round, state_t* state, const uint8_t* round_key){
  uint8_t i,j;

  for (j = 0; j < Nb; j++){
    for (i = 0; i < Nb; i++){
        /* round_key is the result of the key_expansion function, 
        the key block it's not always the same, depends on the round level.
        Since the round key is a vector the column is every 4 bytes */

      (*state)[i][j] ^= round_key[(round * Nb * Nb) + (j * Nb) + i];
    }
  }
}

/* xtime() is the multiplication by x in GF(2^8) */
static uint8_t xtime(uint8_t x){
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

/* multiply() function multiplies by higher power of x in GF(2^8) */
static uint8_t multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
          ((y>>1 & 1) * xtime(x)) ^
          ((y>>2 & 1) * xtime(xtime(x))) ^
          ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); 
}


/* mix_columns() function mixes the columns of the state matrix.
  It's a modular multiplication in GF(2^8) of the polynomial defined by the state 
  column and the fixed polynomial a(x) = 3x^3+x^2+x+2 with modulo x^4+1. */
static void mix_columns(state_t* state){
  uint8_t j;
  uint8_t temp, temp1, temp2;
  for (j = 0; j < Nb; j++)
  {  
    temp2   = (*state)[0][j];
    temp = (*state)[0][j] ^ (*state)[1][j] ^ (*state)[2][j] ^ (*state)[3][j] ;

    temp1  = (*state)[0][j] ^ (*state)[1][j];
    temp1 = xtime(temp1);
    (*state)[0][j] ^= temp1 ^ temp;

    temp1  = (*state)[1][j] ^ (*state)[2][j];
    temp1 = xtime(temp1);  
    (*state)[1][j] ^= temp1 ^ temp;

    temp1  = (*state)[2][j] ^ (*state)[3][j];
    temp1 = xtime(temp1);  
    (*state)[2][j] ^= temp1 ^ temp;

    temp1  =(*state)[3][j] ^ temp2;              
    temp1 = xtime(temp1);  
    (*state)[3][j] ^= temp1 ^ temp;
  }
}

/* the reserse function of mix_column() has a different matrix to multiply by the column. */
static void r_mix_column(state_t* state)
{
  uint8_t j;
  uint8_t a, b, c, d;
  for (j = 0; j < Nb; j++)
  { 
    a = (*state)[0][j];
    b = (*state)[1][j];
    c = (*state)[2][j];
    d = (*state)[3][j];

    (*state)[0][j] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
    (*state)[1][j] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
    (*state)[2][j] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
    (*state)[3][j] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
  }
}

/* Key Schedule generation */
static void key_expansion(uint8_t* round_key, const uint8_t* key){
  uint8_t i, j, k;
  uint8_t temp[Nb]; 
  
  /* The first round key is the key itself */
  for (i = 0; i < Nk; i++){
    round_key[(i * Nb) + 0] = key[(i * Nb) + 0];
    round_key[(i * Nb) + 1] = key[(i * Nb) + 1];
    round_key[(i * Nb) + 2] = key[(i * Nb) + 2];
    round_key[(i * Nb) + 3] = key[(i * Nb) + 3];
  }

  /* To find the other round keys we start from the last column computed */
  for (i = Nk; i < (Nb * (Nr+1)); i++){
    
    k = (i - 1) * Nb;
    temp[0]=round_key[k + 0];
    temp[1]=round_key[k + 1];
    temp[2]=round_key[k + 2];
    temp[3]=round_key[k + 3];

    
    /* At the beginning of each new block */
    if (i % Nk == 0){
      
      /* rot_word() shifts left 4 bytes by one position 
        [a0,a1,a2,a3] becomes [a1,a2,a3,a0]             */
      uint8_t temp1 = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = temp1;
      

      /* sub_word() is a function that takes a 4 byte input word and 
       applies the S-box to each of the four bytes to produce an output word. */
      temp[0] = get_sbox(temp[0]);
      temp[1] = get_sbox(temp[1]);
      temp[2] = get_sbox(temp[2]);
      temp[3] = get_sbox(temp[3]);

      /* because the others are xored with 0, only the first word of the column is computed*/
      temp[0] = temp[0] ^ rcon[i/Nk]; 
    }
    /* The following part is valid only for AES-256 */
    if (i % Nk == Nb){
      /* sub_word() */
      temp[0] = get_sbox(temp[0]);
      temp[1] = get_sbox(temp[1]);
      temp[2] = get_sbox(temp[2]);
      temp[3] = get_sbox(temp[3]);
      
    }

    /* Final step */
    j = i * Nb; 
    k=(i - Nk) * Nb;

    round_key[j + 0] = round_key[k + 0] ^ temp[0];
    round_key[j + 1] = round_key[k + 1] ^ temp[1];
    round_key[j + 2] = round_key[k + 2] ^ temp[2];
    round_key[j + 3] = round_key[k + 3] ^ temp[3];
  }
}

/* Cipher block to encrypt, given a block of 16 bytes of the plaintext produce a block of 16 bytes of the ciphertext */ 
static void cipher(state_t* state, char *key){
  uint8_t round = 0;
  uint8_t round_key[AES_KEYEXPLEN];

  /* Key expansion is used to have a different key every round */
  key_expansion(round_key,key);
  add_round_key(0,state, round_key);
  /* Number of rounds is key length dependent */
  /* First Nr-1 rounds are equal and the last one is without mix_columns() */
  for (round = 1; round < Nr ; round++)
  {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(round, state, round_key);
  }
  /* Last round */
  sub_bytes(state);
  shift_rows(state);
  add_round_key(Nr, state, round_key);

}

/* AES-256 ECB electronic codebook, the plaintext is in payload variable, and the ciphertext in the output variable.
The plaintext encryption is done State by State. */
int encrypt_ecb(char *payload, unsigned short len, char *key, char *output){
  uint8_t i,j,k = 0;
  state_t state;

  int unroll = 0;

  while(k<len){
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        if(k<len){
        state[i][j] = (uint8_t) payload[k];
        k++;
        }else{
           state[i][j] = '\0'; /* padding with \0 */
        }
      }
    }
    #ifdef __DEBUG
    trace_printf("\n########## BLOCK %d ##########\n", k/16);
    trace_printf("\nInput block in cipher ecb\n");
    print_state(&state);
    #endif
    /* encryption of the State */ 
    cipher(&state, key);

    #ifdef __DEBUG
    trace_printf("\nOutput block in cipher ecb\n");
    print_state(&state);
    #endif

    /* Unroll state to fill output array */
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        output[unroll++] = state[i][j];
      }
    }
  }
  return unroll;
}

/* Transform the Initial Vector  used in CBC mode to be able to perform the first XOR opoeration with the State correctly */
static void matrix_iv(state_t *iv){
  uint8_t i,j;
  uint8_t temp;  
    for (i=0;i<Nb;i++){
      for(j=0;j<Nb;j++){
        if(i>j){
          temp=(*iv)[i][j];
          (*iv)[i][j]=(*iv)[j][i];
          (*iv)[j][i]=temp;
        }
    }    
  }
}

/* Encryption standard is AES-256 with CBC as operation mode, padding of the block is done with "\0". 
Initial vector is hardcoded. */
int encrypt_cbc(char *payload, unsigned short len, char *key, char *output){
  uint8_t i,j,k = 0;
  state_t state;
  state_t iv_temp;
  
  int unroll = 0;

  #ifdef __DEBUG
  trace_printf("\nIV\n");
  print_state(&iv);
  #endif
  state_cpy(&iv_temp,&iv);
  matrix_iv(&iv_temp);
	#ifdef __DEBUG
  print_state(&iv_temp);
	#endif

  while(k<len){
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        if(k<len){
        state[i][j] = (uint8_t) payload[k];
        k++;
        }else{
           state[i][j] = '\0'; /* padding with \0 */
        }
      }
    }
    #ifdef __DEBUG
    trace_printf("\n########## BLOCK %d ##########\n", k/16);
    trace_printf("\nInput block in cipher cbc\n");
    print_state(&state);
    #endif
    /* XOR the first State with IV, then with the ciphertext of the previous encryption */
    state_xor(&state,&iv_temp);
    cipher(&state, key);

    #ifdef __DEBUG
    trace_printf("\nOutput block in cipher cbc\n");
    print_state(&state);
    #endif

    state_cpy(&iv_temp,&state); /* So the next cycle the ciphertext is XORed with the next plaintext */

    /* Unroll state to fill output array */
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        output[unroll++] = state[i][j];
      }
    }
  }
  return unroll;
}
/* Reverse cipher block to decrypt a State block of  16 bytes */
static void r_cipher(state_t* state, char *key){
  uint8_t round;
  uint8_t round_key[AES_KEYEXPLEN];
  
  key_expansion(round_key,key);
  add_round_key(Nr,state,round_key);

  for(round = Nr - 1; ; round--){
      r_shift_row(state);
      r_sub_bytes(state);
      add_round_key(round,state, round_key);

      if(round == 0){
        break;
      }
      r_mix_column(state);
  }
}
/* Decryption in ECB, given a ciphertext produce a pleintext. */
void decrypt_ecb(char *payload, unsigned short len, char *key, char *output){
  uint8_t i,j,k = 0;
  state_t state;

  int unroll = 0;

  while(k<len){
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
          state[i][j] = (uint8_t) payload[k++];
      }
    }
    #ifdef __DEBUG
    trace_printf("\nInput block in reverse cipher\n");
    print_state(&state);
    #endif
    r_cipher(&state, key);
    #ifdef __DEBUG
    trace_printf("\nOutput block in reverse cipher\n");
    print_state(&state);
    trace_printf("\n");
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        trace_printf("%c",state[i][j]);
      }
    }
    trace_printf("\n");
    #endif

    /* Unroll state to fill output array */
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
         if(unroll<len){
          output[unroll++] = state[i][j];
        }
      }
    }
  }
}
/* Decryption in CBC.*/
void decrypt_cbc(char *payload, unsigned short len, char *key, char *output){
  uint8_t i,j,k = 0;
  state_t state;
  state_t iv_next,iv_temp;

  int unroll = 0;

  
  #ifdef __DEBUG
  print_state(&iv);
  #endif
  state_cpy(&iv_temp,&iv);
  matrix_iv(&iv_temp);

  while(k<len){
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
          state[i][j] = (uint8_t) payload[k++];
      } 
    }
    state_cpy(&iv_next,&state); /* So the next cycle the cipher text is xored with the next plaintext */
    #ifdef __DEBUG
    trace_printf("\nInput block in reverse cipher\n");
    print_state(&state);
    #endif
    r_cipher(&state, key);
    state_xor(&state,&iv_temp);
    state_cpy(&iv_temp,&iv_next);
    #ifdef __DEBUG
    trace_printf("\nOutput block in reverse cipher\n");
    print_state(&state);
    trace_printf("\n");
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        trace_printf("%c",state[i][j]);
      }
    }
    trace_printf("\n");
    #endif

    /* Unroll state to fill output array */
    for(j=0;j<Nb;j++){
      for(i=0;i<Nb;i++){
        if(unroll<len){
          output[unroll++] = state[i][j];
        }
      }
    }
  }
}

