//
// Created by PC on 10/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H

#ifndef SECP256R1_ARG_NONNULL
#if defined(__GNUC__) || defined(__clang__)
#  define SECP256R1_ARG_NONNULL(x) __attribute__ ((__nonnull__(x)))
#else
#  define SECP256R1_ARG_NONNULL(x)
#endif
#endif

#define RSA3072_PUBLIC_KEY_SIZE   (384)  // Modulo size
#define RSA3072_CIPHERTEXT_SIZE   (384)  // RSA 3072-bit output
#define RSA3072_PRIVATE_KEY_SIZE  (1536)  //
#define RSA3072_PLAINTEXT_SIZE     (32)  // Max plaintext (256 bits)

typedef struct rsa_public_key {
    unsigned char data[RSA3072_PUBLIC_KEY_SIZE];
} rsa_public_key;

typedef struct rsa_private_key {
    unsigned char data[RSA3072_PRIVATE_KEY_SIZE];
} rsa_private_key;

/** Opaque data structure that holds an RSA encryption key-pair consisting of a public and a private key.
 *
 * The public exponent is fixed to 65537 in the current implementation, and the modulus is 3072 bits long.
 * The private key is stored in a format suitable for use with the RSA encryption and decryption functions provided by the library.
 */
typedef struct rsa_keypair{
    rsa_public_key public_key;
    rsa_private_key private_key;
} rsa_keypair;

/** Generate a keypair for RSA encryption.
 *
 *  Returns: 1 if the keypair was successfully generated. 0 will cause commitment to fail.
 *  Args:
 *  Out: keypair: pointer to a keypair object to be filled with the generated keypair.
 *  In: data: arbitrary data pointer that is passed through to the nonce generation function.
 *
 *  The generated RSA keypair will have a fixed public exponent of 65537 and a modulus of 3072 bits.
 *  The private key will be stored in a format suitable for use with the RSA encryption and decryption functions provided by the library.
 */
int secp256r1_rsa_keypair_generate(
        rsa_keypair *keypair,
        void *data
) SECP256R1_ARG_NONNULL(1);

/** Get the public key from an RSA keypair.
 *
 *  Returns: 1 always.
 *  Args:
 *  Out: pubkey: pointer to an rsa_public_key object, set to the keypair public key.
 *  In: keypair: pointer to a keypair.
 */
int secp256r1_rsa_keypair_pubkey_get(
        rsa_public_key *pubkey,
        const rsa_keypair *keypair
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Get the private key from an RSA keypair.
 *
 *  Returns: 1 always.
 *  Args:
 *  Out: privkey: pointer to an rsa_private_key object, set to the keypair private key.
 *  In: keypair: pointer to a keypair.
 */
int secp256r1_rsa_keypair_privkey_get(
        rsa_private_key *privkey,
        const rsa_keypair *keypair
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Free the memory associated with an RSA keypair.
 *
 *  Returns: 1 always.
 *  Args:
 *  In: keypair: pointer to a keypair to be freed. After this call, the keypair should not be used again.
 */
int secp256r1_rsa_keypair_free(
        rsa_keypair *keypair
) SECP256R1_ARG_NONNULL(1);

/** Encrypt a plaintext message using an RSA public key.
 *
 *  Returns: 1 if the encryption was successful. 0 will cause commitment to fail.
 *  Args:
 *  Out: ciphertext: pointer to a buffer of size RSA3072_CIPHERTEXT_SIZE to be filled with the resulting ciphertext.
 *  In: pubkey: pointer to an rsa_public_key object containing the public key to encrypt with.
 *      plaintext: pointer to a buffer containing the plaintext message to be encrypted. The plaintext must be exactly RSA3072_PLAINTEXT_SIZE bytes long (32 bytes).
 */
int secp256r1_rsa_encrypt(
        unsigned char *ciphertext,
        const rsa_public_key *pubkey,
        const unsigned char *plaintext
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Decrypt a ciphertext message using an RSA private key.
 *
 *  Returns: 1 if the decryption was successful. 0 will cause recovery to fail.
 *  Args:
 *  Out: plaintext: pointer to a buffer of size RSA3072_PLAINTEXT_SIZE to be filled with the resulting plaintext message.
 *  In: privkey: pointer to an rsa_private_key object containing the private key to decrypt with.
 *      ciphertext: pointer to a buffer containing the ciphertext message to be decrypted. The ciphertext must be exactly RSA3072_CIPHERTEXT_SIZE bytes long (384 bytes).
 */
int secp256r1_rsa_decrypt(
        unsigned char *plaintext,
        const rsa_private_key *privkey,
        const unsigned char *ciphertext
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Serialize an RSA public key to bytes for transmission.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer (RSA3072_PUBLIC_KEY_SIZE bytes)
 * In:      keypair: pointer to the keypair containing the public key
 */
int secp256r1_rsa_public_key_serialize(
        unsigned char *output,
        const rsa_keypair *keypair
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse an RSA public key from bytes.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     pubkey: pointer to a public key structure.
 * In:      input: pointer to serialized public key (RSA3072_PUBLIC_KEY_SIZE bytes)
 */
int secp256r1_rsa_public_key_parse(
        rsa_public_key *pubkey,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_RSAKEYS_H
