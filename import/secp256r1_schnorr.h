//
// Created by PC on 12/03/2026.
//

#ifndef SECP256R1_SCHNORR_H
#define SECP256R1_SCHNORR_H

#include "stdint.h"
#include "stddef.h"

/** Unless explicitly stated all pointer arguments must not be NULL.
 *
 * The following rules specify the order of arguments in API calls:
 *
 * 1. Context pointers go first, followed by output arguments, combined
 *    output/input arguments, and finally input-only arguments.
 * 2. Array lengths always immediately follow the argument whose length
 *    they describe, even if this violates rule 1.
 * 3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
 *    later go first. This means: signatures, public nonces, secret nonces,
 *    messages, public keys, secret keys, tweaks.
 * 4. Arguments that are not data pointers go last, from more complex to less
 *    complex: function pointers, algorithm names, messages, void pointers,
 *    counts, flags, booleans.
 * 5. Opaque data pointers follow the function pointer they are to be passed to.
 */

/** Opaque data structure that holds context information
 *
 *  The primary purpose of context objects is to store randomization data for
 *  enhanced protection against side-channel leakage. This protection is only
 *  effective if the context is randomized after its creation. See
 *  secp256r1_context_create for creation of contexts and
 *  secp256r1_context_randomize for randomization.
 *
 *  A secondary purpose of context objects is to store pointers to callback
 *  functions that the library will call when certain error states arise. See
 *  secp256r1_context_set_error_callback as well as
 *  secp256r1_context_set_illegal_callback for details.
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API calls that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  secp256r1_context_destroy, secp256r1_context_preallocated_destroy,
 *  and secp256r1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */
typedef struct secp256r1_context_struct secp256r1_context;

/** A pointer to a function to generate a random scalar nonce.
 *
 * Returns: 1 if a nonce was successfully generated. 0 will cause commitment to fail.
 * Out:     nonce32:   pointer to a 32-byte array to be filled with a function that generates a random scalar in Z_q
 * In:      data:      arbitrary data pointer that is passed through
 *          attempt:   how many iterations we have tried to find a valid nonce
 *
 * The generated nonce MUST be non-zero modulo the group order q.
 * For reproducibility in test environments, the function may optionally use
 * a deterministic derivation based on the attempt counter.
 */
typedef int (*secp256r1_nonce_gen_function)(
        unsigned char *nonce32,
        void *data,
        unsigned int attempt
);

/**  When this header is used at build-time the SECP256K1_BUILD define needs to be set
 *  to correctly setup export attributes and nullness checks.  This is normally done
 *  by secp256k1_schnorr.c but to guard against this header being included before secp256k1_schnorr.c
 *  has had a chance to set the define (e.g. via test harnesses that just includes
 *  secp256k1_schnorr.c) we set SECP256K1_NO_BUILD when this header is processed without the
 *  BUILD define so this condition can be caught.
 */
#ifndef SECP256K1_BUILD
# define SECP256K1_NO_BUILD
#endif

/** Warning attributes
 * NONNULL is not used if SECP256R1_BUILD is set to avoid the compiler optimizing out
 * the null checks. */
# if defined(__GNUC__) && SECP256R1_GNUC_PREREQ(3, 4)
#  define SECP256R1_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define SECP256R1_WARN_UNUSED_RESULT
# endif
# if !defined(SECP256R1_BUILD) && defined(__GNUC__) && SECP256R1_GNUC_PREREQ(3, 4)
#  define SECP256R1_ARG_NONNULL(_x)  __attribute__ ((__nonnull__(_x)))
# else
#  define SECP256R1_ARG_NONNULL(_x)
# endif

/** All flags' lower 8 bits indicate what they're for. Do not use directly. */
#define SECP256R1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256R1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256R1_FLAGS_TYPE_COMPRESSION (1 << 1)
/** The higher bits contain the actual data. Do not use directly. */
#define SECP256R1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256R1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256R1_FLAGS_BIT_CONTEXT_DECLASSIFY (1 << 10)
#define SECP256R1_FLAGS_BIT_COMPRESSION (1 << 8)

/** Flag to pass to secp256k1_schnorr_pubkey_serialize. */
#define SECP256R1_SCHNORR_COMPRESSED (SECP256R1_FLAGS_TYPE_COMPRESSION | SECP256R1_FLAGS_BIT_COMPRESSION)
#define SECP256R1_SCHNORR_UNCOMPRESSED (SECP256R1_FLAGS_TYPE_COMPRESSION)

/** Prefix byte used to tag various encoded curvepoints for specific purposes */
#define SECP256R1_TAG_PUBKEY_EVEN 0x02
#define SECP256R1_TAG_PUBKEY_ODD 0x03
#define SECP256R1_TAG_PUBKEY_UNCOMPRESSED 0x04

/** TODO Context logic missing
 */

/** A Schnorr signature in this implementation consists of two values:
 *
 * - e: Which is the truncated hash of the message and the challenge R. It is 16 bytes long.
 * - s: Which is the response to the challenge. It is 32 bytes long.
 */
#define ECDSA_SCHNORR_SIGNATURE_SIZE (48)
#define SECP256R1_MAX_COMMITMENT_SIZE (65) // Max size for committed data (e.g., uncompressed point)

/** Private secret indexed scalar.
 *
 * Represents a private secret scalar value associated with a specific generator index.
 *
 */
typedef struct {
    uint32_t generator_index;
    unsigned char value[32];
} secp256r1_private_secret_scalar;

/** Public point on the curve.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in uncompressed format, which consists of a 0x04 prefix followed by the x and y coordinates (32 bytes each).
 */
typedef  struct {
    uint32_t generator_index;
    unsigned char value[65];
} secp256r1_point_extended;

/** Public point on the curve in x-only format.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in x-only format, which consists of only the x coordinate and the byte to indicate if the point is even
 * or odd (33 bytes).
 */
typedef struct {
    uint32_t generator_index;
    unsigned char value[33];
} secp256r1_point_xonly;

/** Opaque data structure that holds a parsed and valid public key.
 *
 *  It is guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  To convert to a format suitable for storage or transmission,
 *  use secp256k1_schnorr_pubkey_serialize and secp256k1_schnorr_pubkey_parse.
 *  To compare keys, use secp256k1_schnorr_pubkey_cmp.
 */
typedef struct secp256r1_schnorr_pubkey {
    secp256r1_point_extended point; // 65 bytes
} secp256r1_schnorr_pubkey;

/** Opaque data structure that holds a parsed and valid private key.
 *
 *  It is guaranteed to be 32 bytes in size, and can be safely copied/moved.
 *  To convert to a format suitable for storage or transmission, use
 *  secp256r1_schnorr_seckey_serialize and secp256r1_schnorr_seckey_parse.
 */
typedef struct secp256r1_schnorr_seckey {
    secp256r1_private_secret_scalar scalar; // 32 bytes
} secp256r1_schnorr_seckey;

/** Shamir polynomial.
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

/** Share of the group secret key.
 *
 * The secret share results from evaluating the (generator) Shamir polynomial in the receiver index point.
 * For reference, these are the y_i_j values computed in KeyGen4 in the Utils_for_PoC.pdf file.
 */
typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    unsigned char value[32];
} secp256r1_keygen_shamir_secret_share;

/** Hash-based commitment scheme
 *
 * Commitment = H(nonce || value), where nonce is a fresh random 32-byte value
 * and value is the serialized representation of the committed data.
 * The hash function used is SHAKE_256.
 */
typedef struct {
    unsigned char data[32];  // H(nonce || value)
} secp256r1_commitment;

/** Decommitment data for opening a commitment
 *
 * To verify a commitment, the recipient recomputes H(nonce || value)
 * and compares with the commitment.
 */
typedef struct {
    unsigned char nonce[32];                           // Random nonce
    unsigned char value[SECP256R1_MAX_COMMITMENT_SIZE]; // Serialized value. Could be an EC point or a scalar.
    uint32_t value_len;                                   // Actual length used
} secp256r1_decommitment;

/** Packet containing a commitment and the corresponding decommitment for a specific generator index.
 *
 * This packet is used to transmit both the commitment and the decommitment data for a specific generator index.
 * It contains:
 * - generator_index: The index of the generator associated with the commitment and decommitment.
 * - commitment: The hash-based commitment value.
 * - decommitment: The data required to open the commitment, including the nonce and the serialized value.
 */
typedef struct {
    uint32_t generator_index;
    secp256r1_commitment commitment;
    secp256r1_decommitment decommitment;
} secp256r1_commitment_packet;

/** NIZKP for the correctness of a Shamir secret share.
 *
 * This NIZKP proves that a given Shamir secret share is correctly computed according to the corresponding Shamir polynomial.
 * It consists of four values:
 * - u: A point of the curve, stored in uncompressed format (65 bytes). Computed as G * r, where:
 *    - G is the generating point of the curve
 *    - r is a random scalar value used in the proof
 * - c: The challenge, which is 32 bytes long.
 * - z: The response, which is 32 bytes long.
 * - h: A point of the curve, stored in uncompressed format (65 bytes). Computed as G * x, where:
 *     - G is the generating point of the curve
 *     - x is the secret scalar value to prove
 */
typedef struct {
    unsigned char u[65];
    unsigned char c[32];
    unsigned char z[32];
    unsigned char h[65];
} secp256r1_nizkp;

/** Packet containing recovery information for a specific generator index.
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

/** Schnorr's signature challenge e = H(m || R)
 *
 * This structure represents the challenge component of a Schnorr signature.
 */
typedef struct {
    unsigned char value[16];
} secp256r1_schnorr_hash_challenge;

/** Schnorr's signature response s = r + e * x
 *
 * This structure represents the cumulative response component of a Schnorr signature.
 * Computed as the sum of the indexed responses s_i from all the signers, where each s_i is computed as s_i = r_i + e * x_i.
 */
typedef struct {
    unsigned char value[32];
} secp256r1_schnorr_response;

/** Opaque data structure that holds a parsed ECDSA signature.
  *
  * This structure is opaque and should not be accessed directly by users of the library.
  * It is used internally to represent a parsed ECDSA signature, which consists of two components:
  * - e: The truncated hash of the message and the challenge R, which is 16 bytes long.
  * - s: The response to the challenge, which is 32 bytes long.
  *
  * It is guaranteed to be 48 bytes in size.
  * To convert to a format suitable for storage or transmission, use secp256k1_schnorr_signature_serialize and secp256k1_schnorr_signature_parse.
  * To compare signatures, use secp256k1_schnorr_signature_cmp.
  *
  */
typedef struct {
    unsigned char e[16];
    unsigned char s[32];
} secp256r1_schnorr_signature;

/** A safe nonce generation function. */
SECP256R1_API const secp256r1_nonce_gen_function secp256r1_nonce_gen_function_default;

/* ========================================================================
 * Key Generation API
 * ======================================================================== */

/** First phase of Schnorr key generation protocol.
 * Generates random values for {a_i, y_{3_i}, m_i} and the corresponding commitments.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:                pointer to a context object.
 * Out:     sec_scalar_array:   pointer to an array of secp256r1_private_secret_scalar structures
 *                              filled with a_i and m_i for each generator index.
 *          sam_sec_share:      pointer to a secp256r1_keygen_shamir_secret_share structure to be filled with y_3_i for the generator index.
 *          ec_points_array:    pointer to an array of secp256r1_point_extended structures
 *                              filled with the public points corresponding to a_i, y_{3_i} for each generator index.
 *          commitment_packets: pointer to an array of secp256r1_commitment_packet structures
 *                              filled with the generated commitments and decommitments.
 * In:      generator_index:    the index of the generator for which the key generation is being performed.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_phase1(
        const secp256r1_context *ctx,
        secp256r1_private_secret_scalar *sec_scalar_array,
        secp256r1_keygen_shamir_secret_share *sam_sec_share,
        secp256r1_point_extended *ec_points_array,
        secp256r1_commitment_packet *commitment_packets,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5);

/** Second phase of Schnorr key generation protocol.
 * Computes the Shamir secret shares and encrypts them for the receivers.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:                 pointer to a context object.
 * Out:     sam_sec_share_array: pointer to an array of secp256r1_keygen_shamir_secret_share structures
 *                               filled with the evaluations of the Shamir polynomial.
 *          M_i:                 pointer to a secp256r1_point_extended structure filled
 *                               with the public point corresponding to m_i for the generator index.
          recovery_packet:       pointer to a secp256r1_keygen_recovery_packet structure filled with
                                 the encrypted shares and that should be completed inserting the
                                 NIZKPs for the generator index.
 * In:      sec_scalar_array:    pointer to an array of secp256r1_private_secret_scalar structures
 *                               containing a_i and m_i for each generator index.
 *          sam_sec_share_y_3_i: pointer to a secp256r1_keygen_shamir_secret_share structure containing y_3_i
 *                               for the generator index.
 *          enc_pubkey:          pointer to an RSA-3072 public key.
 *          generator_index:     the index of the generator for which the key generation
 *                               is being performed.
 *
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_phase2(
        const secp256r1_context *ctx,
        secp256r1_keygen_shamir_secret_share *sam_sec_share_array,
        secp256r1_point_extended *M_i,
        secp256r1_keygen_recovery_packet *recovery_packet,
        const secp256r1_private_secret_scalar *sec_scalar_array,
        const secp256r1_keygen_shamir_secret_share *sam_sec_share_y_3_i,
        const RSA3072_public_key *enc_pubkey,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5) SECP256R1_ARG_NONNULL(6) SECP256R1_ARG_NONNULL(7);

/** Compute and add the NIZKPs for the recovery packet of a specific generator index.
 * This function should be called after the recovery packet has been filled with the encrypted shares.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:            pointer to a context object.
 * In/Out: recovery_packet: pointer to a secp256r1_keygen_recovery_packet structure
 *                          to be filled with the NIZKPs for the generator index.
 * In:  nonce_fp:           pointer to a function that generates a secure random or deterministic nonce.
 *                          This function should fill the provided 32-byte array with a random nonce and return 1 on success,
 *                          or 0 on failure.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_compute_nizkps(
        const secp256r1_context *ctx,
        secp256r1_keygen_recovery_packet *recovery_packet,
        secp256r1_nonce_gen_function noncefp
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Verify the NIZKPs for the recovery packet of a specific generator index.
 *
 * Returns: 0 if the arguments are invalid or the NIZKPs do not verify. 1 otherwise.
 * Args:    ctx:            pointer to a context object.
 * In:      recovery_packet: pointer to a secp256r1_keygen_recovery_packet structure
 *                          containing the NIZKPs to verify for the generator index.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_verify_nizkps(
        const secp256r1_context *ctx,
        const secp256r1_keygen_recovery_packet *recovery_packet
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Verify public shares correctness.
 * This function verifies that the public shares Y_{3_i} and M_i for a specific generator index
 * are correctly computed according to the Shamir polynomial.
 *
 * Returns: 0 if the arguments are invalid or the shares do not verify. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * In:   y_j_i:              pointer to a secp256r1_secret_share structure containing the share y_{j_i} to verify.
 *       M_j:                pointer to a secp256r1_point_extended structure containing the public point M_j to verify.
 *       A_j:                pointer to a secp256r1_point_extended structure containing the public point A_j.
 *       generator_index:    the index of the generator for which the shares are being verified.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_verify_public_shares(
        const secp256r1_context *ctx,
        const secp256r1_keygen_shamir_secret_share *y_j_i,
        const secp256r1_point_extended *M_j,
        const secp256r1_point_extended *A_j,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Generate the private key omega for Shamir signatures.
 * This function computes the private key for Shamir signatures for a specific generator index
 * by summing the received secret shares from the other parties.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * Out:     schnorr_seckey:   pointer to a secp256r1_schnorr_seckey structure to be filled
 *                           with the generated private key for the generator index.
 * In:      sec_share_array: pointer to an array of secp256r1_keygen_shamir_secret_share structures
 *                           containing the received secret shares from the other parties for each generator index.
 *          n_shares:        number of elements in the sec_share_array.
 *          generator_index: the index of the generator for which the private key is being generated.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_generate_seckey(
        const secp256r1_context *ctx,
        secp256r1_schnorr_seckey *schnorr_seckey,
        const secp256r1_keygen_shamir_secret_share *sec_share_array,
        uint32_t n_shares,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Initiates a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function generates the commitment u and the nonce r for the proof.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * Out:     u:               pointer to a secp256r1_point_extended structure to be filled
 *                           with the generated commitment R for the proof.
 *          r:               pointer to a 32-byte array to be filled with the generated nonce r for the proof.
 * In:      schnorr_seckey:  pointer to a secp256r1_schnorr_seckey structure containing the secret key for which the proof is being generated.
 *          nonce_fp:        pointer to a function that generates a secure random or deterministic nonce.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_prove_knowledge(
        const secp256r1_context *ctx,
        secp256r1_point_extended *u,
        unsigned char *r,
        const secp256r1_schnorr_seckey *schnorr_seckey,
        secp256r1_nonce_gen_function noncefp
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5);

/** Validates the commitment of a ZK proof and generates a random challenge for the proof.
 * This function checks that the commitment u is valid and generates a random challenge c for the proof.
 *
 * Returns: 0 if the arguments are invalid or the commitment is not valid. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * Out:     c:               pointer to a 32-byte array to be filled with a random challenge for the proof.
 * In:      u:               pointer to a secp256r1_point_extended structure containing the commitment u for the proof.
 *          h:               pointer to a secp256r1_point_extended structure containing the point
 *                           h = G * x, where G is the generator of the curve and x is the secret scalar value to prove.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_generate_challenge(
        const secp256r1_context *ctx,
        unsigned char *c,
        const secp256r1_point_extended *u
        const secp256r1_point_extended *h
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Generates the response for a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function computes the response z for the proof using the nonce r and the challenge c.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * Out:     z:               pointer to a 32-byte array to be filled with the generated response for the proof.
 * In:      schnorr_seckey:  pointer to a secp256r1_private_secret_scalar structure containing the secret key
 *                           for which the proof is being generated.
 *          c:               pointer to a 32-byte array containing the challenge c for the proof.
 *          r:               pointer to a 32-byte array containing the nonce r for the proof.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_generate_response(
        const secp256r1_context *ctx,
        unsigned char *z,
        const secp256r1_private_secret_scalar *schnorr_seckey,
        const unsigned char *c,
        const unsigned char *r
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5);

/** Validates a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function checks that the response z is valid for the given commitment u and challenge c.
 *
 * Returns: 0 if the arguments are invalid or the proof does not verify. 1 otherwise.
 * Args:    ctx:             pointer to a context object.
 * In:      schnorr_pubkey:  pointer to a secp256r1_point_extended structure containing the point corresponding to
 *                           the secret to prove.
 *          u:               pointer to a secp256r1_point_extended structure containing the commitment u for the proof.
 *          c:               pointer to a 32-byte array containing the challenge c for the proof.
 *          z:               pointer to a 32-byte array containing the response z for the proof.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_verify_proof(
        const secp256r1_context *ctx,
        const secp256r1_point_extended *schnorr_pubkey,
        const secp256r1_point_extended *u,
        const unsigned char *c,
        const unsigned char *z
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5);

/* ========================================================================
 * Ordinary Signature API
 * ======================================================================== */

/** First phase of Schnorr signing protocol.
 * Generates random value for r_i and the corresponding commitment.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:                pointer to a context object.
 * Out:     sec_scalar: pointer to a secp256r1_private_secret_scalar containing the scalar nonce k_i.
 *          r_i:                pointer to a secp256k1_point_extended structure to be filled with
 *                              the public point corresponding to r_i for the generator index.
 *          commitment_packet:  pointer to a secp256r1_commitment_packet structure filled with
 *                              the generated commitment and decommitment for r_i
 * In:      nonce_fp:           pointer to a function that generates a secure random or deterministic nonce.
 *          generator_index:    the index of the generator for which the signing is being performed.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_sign_phase1(
        const secp256r1_context *ctx,
        secp256r1_private_secret_scalar *sec_scalar,
        secp256r1_point_extended *r_i,
        secp256r1_commitment_packet *commitment_packet,
        secp256r1_nonce_gen_function nonce_fp,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5);

/** Second phase of Schnorr signing protocol.
 * Computes the challenge e and the response s_i for a specific generator index.
 * Also returns the commitment-decommitment pair for s_i.
 *
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:                pointer to a context object.
 * Out:     schnorr_signature_chall:     pointer to a secp256r1_schnorr_hash_challenge.
 *          schnorr_signature_part_resp: pointer to a secp256r1_schnorr_response.
 *          commitment_packet:           pointer to a secp256r1_commitment_packet structure filled with
 *                                       the generated commitment and decommitment for s_i.
 * In:      schnorr_seckey:          pointer to a secp256r1_schnorr_seckey structure containing the secret key
 *                                   for which the signing is being performed.
 *          sec_scalar:              pointer to a secp256r1_private_secret_scalar structure containing the scalar nonce k_i for the generator index.
 *          message:                 pointer to the message being signed.
 *          message_len:             length of the message being signed.
 *          nonce_array:             pointer to an array of secp256r1_point_xonly structures containing the public nonces R.
 *          generator_index:         the index of the generator for which the signing is being performed.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_sign_phase2(
        const secp256r1_context *ctx,
        secp256r1_schnorr_hash_challenge *schnorr_signature_chall,
        secp256r1_schnorr_response *schnorr_signature_part_resp,
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_schnorr_seckey *schnorr_seckey,
        const secp256r1_private_secret_scalar *sec_scalar,
        const unsigned char *message,
        uint32_t message_len,
        const secp256r1_point_xonly *nonce_array,
        uint32_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5) SECP256R1_ARG_NONNULL(6) SECP256R1_ARG_NONNULL(7) SECP256R1_ARG_NONNULL(8);

/* ========================================================================
 * Recovery Signature API
 * ======================================================================== */



#endif // SECP256R1_SCHNORR_H
