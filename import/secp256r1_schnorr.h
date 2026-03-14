//
// Created by PC on 12/03/2026.
//

#ifndef SECP256R1_SCHNORR_H
#define SECP256R1_SCHNORR_H

#include "stdint.h"
#include "stddef.h"

/* A Schnorr signature in this implementation consists of two values:
 *
 * - e: Which is the truncated hash of the message and the challenge R. It is 16 bytes long.
 * - s: Which is the response to the challenge. It is 32 bytes long.
 */
#define ECDSA_SCHNORR_SIGNATURE_SIZE (48)

#define RSA3072_PUBLIC_KEY_SIZE   (384)  // Modulo size
#define RSA3072_CIPHERTEXT_SIZE   (384)  // RSA 3072-bit output
#define RSA3072_PLAINTEXT_SIZE     (32)  // Max plaintext (256 bits)

#define SECP256R1_MAX_COMMITMENT_SIZE (65) // Max size for committed data (e.g., uncompressed point)


typedef struct rsa_public_key rsa_public_key;
typedef struct rsa_private_key rsa_private_key;

/* Private secret indexed scalar.
 *
 * Represents a private secret scalar value associated with a specific generator index.
 *
 */
typedef struct {
    uint32_t generator_index;
    unsigned char value[32];
} secp256r1_private_secret_scalar;

/* Public point on the curve.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in uncompressed format, which consists of a 0x04 prefix followed by the x and y coordinates (32 bytes each).
 */
typedef  struct {
    uint32_t generator_index;
    unsigned char value[65];
} secp256r1_point_extended;

/* Public point on the curve in x-only format.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in x-only format, which consists of only the x coordinate (32 bytes).
 */
typedef struct {
    uint32_t generator_index;
    unsigned char value[32];
} secp256r1_point_xonly;

/* Shamir polynomial.
 *
 * Represents a Shamir polynomial associated with a specific generator index.
 * The polynomial is defined by its coefficients, which are stored as two 32-byte values.
 * The polynomial always has a degree of 1, meaning it consists of two coefficients: the constant term and the linear term.
 */
typedef struct {
    uint32_t generator_index;
    unsigned char constant_term[32];
    unsigned char linear_term[32];
} secp256r1_keygen_shamir_polynomial;

/* Share of the group secret key.
 *
 * The secret share results from evaluating the (generator) Shamir polynomial in the receiver index point.
 * For reference, these are the y_i_j values computed in KeyGen4 in the Utils_for_PoC.pdf file.
 */
typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    unsigned char value[32];
} secp256r1_keygen_shamir_secret_share;

/* Hash-based commitment scheme
 *
 * Commitment = H(nonce || value), where nonce is a fresh random 32-byte value
 * and value is the serialized representation of the committed data.
 * The hash function used is SHAKE_256.
 */
typedef struct {
    unsigned char data[32];  // H(nonce || value)
} secp256r1_commitment;

/* Decommitment data for opening a commitment
 *
 * To verify a commitment, the recipient recomputes H(nonce || value)
 * and compares with the commitment.
 */
typedef struct {
    unsigned char nonce[32];                           // Random nonce
    unsigned char value[SECP256R1_MAX_COMMITMENT_SIZE]; // Serialized value
    size_t value_len;                                   // Actual length used
} secp256r1_decommitment;

/* NIZKP for the correctness of a Shamir secret share.
 *
 * This NIZKP proves that a given Shamir secret share is correctly computed according to the corresponding Shamir polynomial.
 * It consists of four values:
 * - u: A point of the curve, stored in uncompressed format (65 bytes). Computed as G * r, where:
 *    - G is the generator point of the curve
 *    - r is a random scalar value used in the proof
 * - c: The challenge, which is 32 bytes long.
 * - z: The response, which is 32 bytes long.
 * - h: A point of the curve, stored in uncompressed format (65 bytes). Computed as G * x, where:
 *     - G is the generator point of the curve
 *     - x is the secret scalar value to prove
 */
typedef struct {
    unsigned char u[65];
    unsigned char c[32];
    unsigned char z[32];
    unsigned char h[65];
} secp256r1_nizkp;

/* Packet containing recovery information for a specific generator index.
 *
 * This packet contains:
 * - the two encryptions of the Shamir secret shares (y_3_i and y_i_3)
 * - two NIZKPs proving the correctness of these shares
 *
 * The shares are encrypted using RSA-3072, and the resulting ciphertext is stored in the packet.
 */
typedef struct {
    uint32_t generator_index;
    unsigned char encrypted_y_3i[RSA3072_CIPHERTEXT_SIZE];
    unsigned char encrypted_y_i3[RSA3072_CIPHERTEXT_SIZE];
    secp256r1_nizkp nizkp_y_3i;
    secp256r1_nizkp nizkp_y_i3;
} secp256r1_keygen_recovery_packet;

/* Schnorr's signature challenge e = H(m || R)
 *
 * This structure represents the challenge component of a Schnorr signature.
 */
typedef struct {
    unsigned char value[16];
} secp256r1_schnorr_hash_challenge;

/* Schnorr's signature response s = r + e * x
 *
 * This structure represents the cumulative response component of a Schnorr signature.
 * Computed as the sum of the indexed responses s_i from all the signers, where each s_i is computed as s_i = r_i + e * x_i.
 */
typedef struct {
    unsigned char value[32];
} secp256r1_schnorr_response;

/* The complete ECDSA signature
 *
 * This structure represents a complete ECDSA signature, which consists of two components:
 * - e: The truncated hash of the message and the challenge R, which is 16 bytes long.
 * - s: The response to the challenge, which is 32 bytes long.
 */
typedef struct {
    unsigned char e[16];
    unsigned char s[32];
} secp256r1_schnorr_signature;

#endif // SECP256R1_SCHNORR_H
