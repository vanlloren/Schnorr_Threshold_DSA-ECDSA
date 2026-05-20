//
// Created by PC on 10/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H

#include <stddef.h>

#ifndef SECP256R1_ARG_NONNULL
#if defined(__GNUC__) || defined(__clang__)
#  define SECP256R1_ARG_NONNULL(x) __attribute__ ((__nonnull__(x)))
#else
#  define SECP256R1_ARG_NONNULL(x)
#endif
#endif

#define RSA3072_CIPHERTEXT_SIZE   (384)  // Output 3072-bit (384 byte)
#define RSA3072_PLAINTEXT_SIZE     (32)  // Max plaintext (256 bit / 32 byte)
#define RSA3072_PUBLIC_KEY_SIZE   (400) // Valore pulito, sicuro e ottimizzato

typedef struct evp_pkey_st EVP_PKEY;

/** Generate a native OpenSSL RSA-3072 keypair.
 *
 * Returns: 1 if the keypair was successfully generated. 0 on failure.
 * Out:
 * pubkey: pointer to an EVP_PKEY* that will hold the generated public key.
 * privkey: pointer to an EVP_PKEY* that will hold the generated private key.
 *
 */
int secp256r1_rsa_keypair_generate(
        EVP_PKEY **pubkey,
        EVP_PKEY **privkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Encrypt a plaintext message using a native RSA public key.
 *
 * Returns: 1 if encryption was successful, 0 on failure.
 * Out: ciphertext: buffer of size RSA3072_CIPHERTEXT_SIZE filled with the result.
 * In:  pubkey: native OpenSSL public key.
 * plaintext: buffer containing the message (must be exactly RSA3072_PLAINTEXT_SIZE bytes).
 * out_len: pointer to size_t set to the length of the ciphertext (will be RSA3072_CIPHERTEXT_SIZE).
 */
int secp256r1_rsa_encrypt(
        unsigned char *ciphertext,
        EVP_PKEY *pubkey,
        const unsigned char *plaintext,
        size_t *out_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Decrypt a ciphertext message using a native RSA private key.
 *
 * Returns: 1 if decryption was successful, 0 on failure.
 * Out: plaintext: buffer of size RSA3072_PLAINTEXT_SIZE filled with the result.
 * In:  privkey: native OpenSSL private key.
 * ciphertext: buffer containing the message (must be exactly RSA3072_CIPHERTEXT_SIZE bytes).
 */
int secp256r1_rsa_decrypt(
        unsigned char *plaintext,
        EVP_PKEY *privkey,
        const unsigned char *ciphertext
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Free the memory associated with a native RSA key (public or private).
 *
 * Returns: 1 always.
 * In: pkey: native OpenSSL key to be freed. After this call, the pointer should not be used.
 */
int secp256r1_rsa_key_free(
        EVP_PKEY *pkey
);

/** Serialize an RSA public key to a binary DER buffer for transmission.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to the destination buffer (must be at least RSA3072_PUBLIC_KEY_SIZE bytes).
 * In:      pubkey: native OpenSSL public key to be serialized.
 */
int secp256r1_rsa_public_key_serialize(
        unsigned char *output,
        EVP_PKEY *pubkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse an RSA public key from a binary DER buffer.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     pubkey_out: pointer to an EVP_PKEY* variable that will hold the parsed public key.
 * In:      input: pointer to the serialized public key buffer (RSA3072_PUBLIC_KEY_SIZE bytes).
 * Note:    The parsed key must be freed by the caller using secp256r1_rsa_key_free().
 */
int secp256r1_rsa_public_key_parse(
        EVP_PKEY **pubkey_out,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H