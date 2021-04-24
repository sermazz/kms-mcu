#ifndef __mod_arith_H
#define __mod_arith_H

/**
 * NUMBER THEORY LIBRARY
 * ---------------------
 * This library contains many functions for the arithmetics of Number theory
 * implemented over 32 bits, including operations in modulus, on prime numbers and
 * with discrete logarithms; they are particularly useful for asymmetric cryptography
 */

/****************************** FUNCTIONS PROTOTYPES *******************************/

// Modular arithmetic
uint32_t mul_mod(uint32_t a, uint32_t b, uint32_t mod);
uint32_t pow_mod(uint32_t base, uint32_t exp, uint32_t mod);

// Prime numbers arithmetic
uint32_t is_sprp(uint32_t n, uint32_t a);
uint32_t is_prime(uint32_t x);
int primitive_root(uint32_t p, uint32_t *root);
uint32_t euler_totient (uint32_t n);
int factorize(uint32_t n, uint32_t *factors, uint8_t array_size);

#endif /* __mod_arith_H */
