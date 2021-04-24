#include <stdio.h>
#include <stdint.h>
// My libraries
#include <numth_arith.h>
#include <rng_custom.h>

/**
 * NUMBER THEORY LIBRARY
 * ---------------------
 * This library contains many functions for the arithmetics of Number theory
 * implemented over 32 bits, including operations in modulus, on prime numbers and
 * with discrete logarithms; they are particularly useful for asymmetric cryptography
 */

/************************************* DEFINES *************************************/

#define __VERBOSE  /* Enable verbose trace_printf errors and messages */


/************************************ CONSTANTS ************************************/

/* Hash table for primality test */
uint16_t bases[] = {
	15591,  2018,  166, 7429,  8064, 16045, 10503,  4399,  1949,  1295, 2776,  3620,   560,  3128,  5212,  2657,
	 2300,  2021, 4652, 1471,  9336,  4018,  2398, 20462, 10277,  8028, 2213,  6219,   620,  3763,  4852,  5012,
	 3185,  1333, 6227, 5298,  1074,  2391,  5113,  7061,   803,  1269, 3875,   422,   751,   580,  4729, 10239,
	  746,  2951,  556, 2206,  3778,   481,  1522,  3476,   481,  2487, 3266,  5633,   488,  3373,  6441,  3344,
	   17, 15105, 1490, 4154,  2036,  1882,  1813,   467,  3307, 14042, 6371,   658,  1005,   903,   737,  1887,
	 7447,  1888, 2848, 1784,  7559,  3400,   951, 13969,  4304,   177,   41, 19875,  3110, 13221,  8726,   571,
	 7043,  6943, 1199,  352,  6435,   165,  1169,  3315,   978,   233, 3003,  2562,  2994, 10587, 10030,  2377,
	 1902,  5354, 4447, 1555,   263, 27027,  2283,   305,   669,  1912,  601,  6186,   429,  1930, 14873,  1784,
	 1661,   524, 3577,  236,  2360,  6146,  2850, 55637,  1753,  4178, 8466,   222,  2579,  2743,  2031,  2226,
	 2276,   374, 2132,  813, 23788,  1610,  4422,  5159,  1725,  3597, 3366, 14336,   579,   165,  1375, 10018,
	12616,  9816, 1371,  536,  1867, 10864,   857,  2206,  5788,   434, 8085, 17618,   727,  3639,  1595,  4944,
	 2129,  2029, 8195, 8344,  6232,  9183,  8126,  1870,  3296,  7455, 8947, 25017,   541, 19115,   368,   566,
	 5674,   411,  522, 1027,  8215,  2050,  6544, 10049,   614,   774, 2333,  3007, 35201,  4706,  1152,  1785,
	 1028,  1540, 3743,  493,  4474,  2521, 26845,  8354,   864, 18915, 5465,  2447,    42,  4511,  1660,   166,
	 1249,  6259, 2553,  304,   272,  7286,    73,  6554,   899,  2816, 5197, 13330,  7054,  2818,  3199,   811,
	 922,    350, 7514, 4452,  3449,  2663,  4708,   418,  1621,  1171, 3471,    88, 11345,   412,  1559,   194
};


/****************************** FUNCTIONS DEFINITIONS ******************************/

/* ------------------------------------------------------------------------------- */
/* ---------------------------- Modular arithmetic ------------------------------- */
/* ------------------------------------------------------------------------------- */

/**
 * Function mul_mod
 * ----------------
 * Compute a*b % mod (a*b product in modulus mod), where a, b and mod are uint32_t; a
 * uint32_t is returned. The algorithm is based on the Russian Peasant multiplication
 * https://en.wikipedia.org/wiki/Ancient_Egyptian_multiplication#Russian_peasant_multiplication
 * In its implementation here, it is used to solve the problem of wrapping around mod
 * but also adjustments are performed to avoid incorrect results due to the intrinsic
 * modular operations with mod=UINT32_MAX, due to the maximum size of the variables.
 */
uint32_t mul_mod(uint32_t a, uint32_t b, uint32_t mod) {
	uint32_t res = 0;
	uint32_t temp_b;

	/* Only needed if b may be >= mod */
	if (b >= mod)
		if (mod > UINT32_MAX / 2u)
			b -= mod;
		else
			b %= mod;

	while (a != 0) {
		if (a & 1) {
			/* Add b to res, modulo mod, without overflow */
			if (b >= mod - res) /* Equiv to if (res + b >= mod), without overflow */
				res -= mod;
			res += b;
		}
		a >>= 1;
		/* Double b, modulo mod */
		temp_b = b;
		if (b >= mod - b) /* Equiv to if (2 * b >= mod), without overflow */
			temp_b -= mod;
		b += temp_b;
	}
	return res;
}

/**
 * Function pow_mod
 * ----------------
 * Compute base^exp % mod (base to the power of exp in modulus mod), where base, exp
 * and mod are uint32_t; a uint32_t is returned. Note that the multiplications
 * res*base and base*base in the body of this function are subject to overflow, which
 * is why the above-defined mul_mod is used instead of common multiplication with
 * modulus operation.
 * For the employed algorithm and its related discussion in the literature: see
 * p.244 of "Schneier, Bruce (1996). Applied Cryptography: Protocols, Algorithms, and
 * Source Code in C. Second Edition. Wiley. ISBN 978-0-471-11709-4.
 */
uint32_t pow_mod(uint32_t base, uint32_t exp, uint32_t mod) {
	uint32_t res = 1;

	base %= mod;
	while (exp > 0) {
		if (exp & 1)
			res = mul_mod(res, base, mod);
		base = mul_mod(base, base, mod);
		exp >>= 1;
	}
	return res;
}


/* ------------------------------------------------------------------------------- */
/* ------------------------- Prime numbers arithmetic ---------------------------- */
/* ------------------------------------------------------------------------------- */

/**
 * Function is_sprp
 * ----------------
 * Function part of the algorithm FJ32_256 for 32-bit numbers primality test; the
 * algorithm is described in: Forišek, Michal, and Jakub Jancina. "Fast Primality
 * Testing for Integers That Fit into a Machine Word⋆." (2015). Available online:
 * http://ceur-ws.org/Vol-1326/020-Forisek.pdf
 * It returns: 0 for false, 1 for true
 */
uint32_t is_sprp(uint32_t n, uint32_t a){
    uint32_t d = n-1;
    uint32_t s = 0;
    while ((d & 1) == 0){
    	s += 1;
    	d >>= 1;
    }

    uint64_t cur = 1;
    uint64_t pw = d;
    while (pw) {
        if (pw & 1)
        	cur = (cur*a) % n;
        a = ((uint64_t)a*a) % n;
        pw >>= 1;
    }

    if (cur == 1)
    	return 1;
    for (uint32_t r=0; r<s; r++) {
        if (cur == n-1)
        	return 1;
        cur = (cur*cur) % n;
    }
    return 0;
}

/**
 * Function is_prime
 * -----------------
 * Top-level function for the FJ32_256 algorithm for 32-bit numbers primality test;
 * the algorithm is described in: Forišek, Michal, and Jakub Jancina. "Fast Primality
 * Testing for Integers That Fit into a Machine Word⋆." (2015). Available online:
 * http://ceur-ws.org/Vol-1326/020-Forisek.pdf
 * This function returns: 1 if x is a prime number, 0 otherwise
 */
uint32_t is_prime(uint32_t x){
    if (x==2 || x==3 || x==5 || x==7)
    	return 1;
    if (x%2==0 || x%3==0 || x%5==0 || x%7==0)
    	return 0;
    if (x<121)
    	return (x>1);

    uint64_t h = x;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) & 255;

    return is_sprp(x,bases[h]);
}

/**
 * Function primitive_root
 * -----------------------
 * Function to find a primitive root of a prime 32-bit number p; it is based on the
 * algorithm described at https://cp-algorithms.com/algebra/primitive-root.html
 * The returned primitive root is a random one among the some big primitive roots
 * found for p, and it gets written in the uint32_t variable pointed by root input
 * pointer.
 * It returns:  1 -> if a primitive root of p is found
 * 			    0 -> if no primitive roots are found
 * 			   -1 -> in case of hard fault
 */
int primitive_root(uint32_t p, uint32_t *root){
	/**
	 * Array of factors of the Euler's totient of input p; phi can have at most 50
	 * factors, otherwise an hard fault is returned; this is due to the impossibility
	 * of using dynamic memory allocation (too small heap)
     */
	uint32_t factors[50];

	uint32_t phi = p - 1; // Euler's totient of a prime number

    int fact_num;
    fact_num = factorize(phi, factors, 50);
	if(fact_num < 0){
		// return error and abort if amount of factors does not fit in allocated memory
		#ifdef __VERBOSE
		trace_printf("ERROR: (numth_arith - 1.1) Error @ factorize in primitive_root.\n");
		#endif
		return -1;
	}

	// Array for some of the biggest primitive roots of p
	uint32_t prim_roots[16];
	uint32_t pr_i = 0; // array first empty pointer

    // Look for primitive roots checking that g^(phi/factor) % p != 1 for each factor of phi (then g is a primitive root)
	// Start checking g from p/10 (to give some slack from p), until enough primitive roots are found or until you reach g=2
	// Note that in our implementation it is always supposed to be p/10 >= 2
    for (uint32_t res = p/10; res >= 2; --res) {
    	uint32_t ok = 1; // ok=1 if (g^(phi/factor) % p) keeps being != 1
        for (uint8_t i = 0; (i < fact_num) && ok; ++i){
            ok &= pow_mod(res, phi / factors[i], p) != 1;
        }
        if (ok){
        	// If res is a primitive root of p, add it to the primitive roots vector
        	if (pr_i < 16)
        		prim_roots[pr_i++] = res;
        	else
        		break; // when the vector is full
        }
    }

    uint32_t rnd;
    int ret;

    if(pr_i){
		ret = rng_get_random32(&rnd);
		if(ret){
			// return error and abort
			#ifdef __VERBOSE
			trace_printf("ERROR: (numth_arith - 1.2) Error @ rng_get_random32 in primitive_root.\n");
			#endif
			return -1;
		}
		rnd = rnd  & 0x0000000F; // random 4-bit number to randomly address prim_roots[16] vector
		*root = prim_roots[rnd]; // random primitive root from the collected biggest 16 ones
		#ifdef __VERBOSE
		trace_printf("MESSAGE: (numth_arith - 1.3) Primitive root of prime %u found: %u.\n", p, prim_roots[rnd]);
		#endif
		return 1;
    }
    else
    	return 0;
}

/**
 * Function euler_totient
 * ----------------------
 * Function to compute the totient of a 32-bit intger n (i.e. all the numbers < n
 * coprime to n), with complexity O(sqrt(n)).
 * The algorithm is described at https://cp-algorithms.com/algebra/phi-function.html
 */
uint32_t euler_totient (uint32_t n){
	uint32_t result = n;

    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) {
            while (n % i == 0)
                n /= i;
            result -= result / i;
        }
    }
    if (n > 1)
        result -= result / n;
    return result;
}

/**
 * Function factorize
 * ------------------
 * Factorize the input uint32_t number n and collect its factors in the uint32_t
 * array pointed by factors, whose max size is defined by the uint8_t array_size.
 * It returns: a non-zero value representing the number of factors found, if the
 *             factorization is successful, -1 if an hard fault occurs
 */
int factorize(uint32_t n, uint32_t *factors, uint8_t array_size){
	uint32_t temp = n;
	uint8_t array_i = 0; // array first empty pointer

    for (uint64_t i = 2; i*i <= (uint64_t)temp; ++i){
        if (temp % i == 0) {
        	if(array_i >= array_size){
    			// return error and abort if amount of factors does not fit in allocated memory
    			#ifdef __VERBOSE
    			trace_printf("ERROR: (numth_arith - 2.1) Error @ array_i >= %hu in factorize.\n", array_size);
    			#endif
    			return -1;
        	}
        	factors[array_i++] = i;
            while (temp % i == 0)
                temp /= i;
        }
    }

    if (temp > 1){
    	if(array_i >= array_size){
			// return error and abort if amount of factors does not fit in allocated memory
			#ifdef __VERBOSE
    		trace_printf("ERROR: (numth_arith - 2.2) Error @ array_i >= %hu in factorize.\n", array_size);
			#endif
			return -1;
    	}
    	factors[array_i++] = temp;
    }

    return array_i;
}
