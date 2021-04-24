#ifndef __eke_exp_H
#define __eke_exp_H

/**
 * ENCRYPTED EXPONENTIAL KEY EXCHANGE KAP LIBRARY
 * ----------------------------------------------
 * This library implements the main functions needed for a Key Agreement Protocol
 * (KAP) built upon a passsword-base Encrypted Key Exchange (EKE) with exponential
 * key exchange. The protocol is implemented on 32 bit data, and its implementation
 * is based on the literature in:
 * Bellovin, Steven Michael, and Michael Merritt. "Encrypted key exchange:
 * Password-based protocols secure against dictionary attacks." (1992).
 *
 * This library contains the functions to implement the following KAP:
 * - [A] publishes alpha and beta unencrypted, generates a random RA and sends to [B]
 *   Enc_P(alpha^RA % beta), where P is the hardwired AES-256 key
 * - [B] decrypts alpha^RA % beta, generates a random RB, computes alpha^RA*RB % beta
 *   and uses it as a seed for HMAC-SHA256 to generate the key K; then sends to [A]
 *   Enc_P(alpha^RB % beta) and Enc_P(challengeB)
 * - [A] computes alpha^RA*RB % beta and generates the same key K, then decrypts the
 *   challengeB, computes its reply and sends to [B] Enc_P(challengeA) and
 *   Enc_P(solution of challengeB)
 * - [B] verifies the solution to challengeB and sends to [A] Enc_P(solution of
 *   challengeA) and an acknowledgment
 * - [A] verifies the solution to challengeA and sens to [B] and acknowledgment,
 *   definitely storing K in the KMS
 * - [B] if it receives the acknowledgment, it stores K in the KMS
 */

/************************************* DEFINES *************************************/

/* Hardcoded password for password-authenticated key exchange (AES-256 encryption) */
#define EKE_AES_KEY      "dh6}!9=Fad;H$gHol2/as@!y#~Fè[JEa"
#define EKE_AES_KEY_LEN  32
/* Key for hashing of the commonly agreed seed, to compute the actual key (HMAC-SHA256) */
#define EKE_HMAC_KEY     "Ku9i3278bdkj/2-12=;´;lmnop8M.,/]-OJ[PÓM3-/=f2;31;,d/w]{nJ2EK2f3e"
#define EKE_HMAC_KEY_LEN 64


/****************************** FUNCTIONS PROTOTYPES *******************************/

// Protocol functions
void eke_init();
int eke_kap_step1_a(uint32_t *ret_beta, uint32_t *ret_alpha, uint8_t *enc_pow_a);
int eke_kap_step2_b(uint32_t beta, uint32_t alpha, uint8_t *enc_pow_a, uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint16_t key_size);
int eke_kap_step3_a(uint8_t *enc_pow_b, uint8_t *enc_chlg_b, uint8_t *enc_reply_a, uint16_t key_size);
int eke_kap_step4_b(uint8_t *enc_reply_a, uint8_t *enc_reply_b);
int eke_kap_step5_a(uint8_t *enc_reply_b, uint32_t key_id, uint32_t key_cryptoperiod);
int eke_kap_step6_b(uint32_t key_id, uint32_t key_cryptoperiod);
void eke_kap_reset();

// Utilities
int generate_beta_alpha(uint32_t *beta, uint32_t *alpha);
uint32_t solve_challenge(uint32_t challenge);

#endif /* __eke_exp_H */
