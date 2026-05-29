//
// Created by PC on 12/03/2026.
//

#ifndef SECP256R1_SCHNORR_H
#define SECP256R1_SCHNORR_H

#include <stdint.h>
#include <stddef.h>
#include "secp256r1_rsakeys.h"
#include "rng.h"
#include "operations_codes.h"
#include "dsc_values.h"
#include <sys/random.h>
#include <openssl/evp.h>

#define SECP256R1_GNUC_PREREQ(maj, min) 1

/** Unless explicitly stated all pointer arguments must not be NULL.
 *
 * The following rules specify the order of arguments in API calls:
 *
 * 1. Array lengths always immediately follow the argument whose length
 *    they describe, even if this violates rule 1.
 * 2. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
 *    later go first. This means: signatures, public nonces, secret nonces,
 *    messages, public keys, secret keys, tweaks.
 * 3. Arguments that are not data pointers go last, from more complex to less
 *    complex: function pointers, algorithm names, messages, void pointers,
 *    counts, flags, booleans.
 * 4. Opaque data pointers follow the function pointer they are to be passed to.
 */

/**  When this header is used at build-time the SECP256R1_BUILD define needs to be set
 *  to correctly setup export attributes and nullness checks.  This is normally done
 *  by secp256r1_schnorr.c but to guard against this header being included before secp256r1_schnorr.c
 *  has had a chance to set the define (e.g. via test harnesses that just includes
 *  secp256r1_schnorr.c) we set SECP256R1_NO_BUILD when this header is processed without the
 *  BUILD define so this condition can be caught.
 */
#ifndef SECP256R1_BUILD
# define SECP256R1_NO_BUILD
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
#  ifndef SECP256R1_ARG_NONNULL
# if defined(__GNUC__) || defined(__clang__)
#  define SECP256R1_ARG_NONNULL(_x) __attribute__ ((__nonnull__(_x)))
# else
#  define SECP256R1_ARG_NONNULL(_x)
# endif
#endif
# endif

/** A Schnorr signature in this implementation consists of two values:
 *
 * - e: Which is the truncated hash of the message and the challenge R. It is 16 bytes long.
 * - s: Which is the response to the challenge. It is 32 bytes long.
 */
#define ECDSA_SCHNORR_SIGNATURE_SIZE (48)
#define SECP256R1_MAX_COMMITMENT_SIZE (65) // Max size for committed data (e.g., uncompressed point)
#define CIPHERTEXT_SIZE (384) // currently RSA 3072-bit output
#define SECP256R1_RECOVERY_PACKET_SIZE (1 + (2 * CIPHERTEXT_SIZE) + (2 * (1 + 65 + 32 + 32 + 65)))
#define SECP256R1_COMMITMENT_BUFFER_SIZE (32)
#define SECP256R1_DECOMMITMENT_BUFFER_SIZE (32 + SECP256R1_MAX_COMMITMENT_SIZE + 4) // nonce + value + value_len
#define SECP256R1_RECOVERY_INFO_BUFFER_SIZE (1 + 34 + (1 + (2 * CIPHERTEXT_SIZE) + (2 * (1 + 65 + 32 + 32 + 65))))
#define SECP256R1_SIGNATURE_RECOVERY_INFO_BUFFER_SIZE (66 + (2 * SECP256R1_RECOVERY_PACKET_SIZE))
#define SECP256R1_POINT_EXTENDED_BUFFER_SIZE (1 + 65) // generator_index + uncompressed point

/** Private secret indexed scalar.
 *
 * Represents a private secret scalar value associated with a specific generator index.
 * Scalars are represented using the big-endian 32-byte format.
 *
 */
typedef struct secp256r1_private_secret_scalar {
    uint8_t generator_index;
    unsigned char value[32];
} secp256r1_private_secret_scalar;

/** Public point on the curve.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in uncompressed format, which consists of a 0x04 prefix
 * followed by the x and y coordinates (32 bytes each) in big-endian format.
 */
typedef struct secp256r1_point_extended {
    uint8_t generator_index;
    unsigned char value[65];
} secp256r1_point_extended;

/** Public point on the curve in x-only format.
 *
 * Represents a public point on the secp256r1 curve associated with a specific generator index.
 * The point is stored in x-only format, which consists of only the x coordinate and the byte to indicate if the point is even
 * or odd (33 bytes).
 */
typedef struct secp256r1_point_xonly {
    uint8_t generator_index;
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

/** Opaque data structure that holds a parsed and valid reduced set of Shamir secret shares.
 *
 * This representation consist in an intermediate step towards the computations of the actual
 * private key for Schnorr signatures.
 * The private key must be computed using secp256r1_schnorr_keygen_generate_seckey.
 */
 typedef struct secp256r1_schnorr_reduced_shamir_shares {
     secp256r1_private_secret_scalar scalar;
 } secp256r1_schnorr_reduced_shamir_shares;

/** Shamir polynomial.
 *
 * Represents a Shamir polynomial associated with a specific generator index.
 * The polynomial is defined by its coefficients, which are stored as two secp256r1_private_secret_scalar structures.
 * The polynomial always has a degree of 1, meaning it consists of two coefficients: the constant term and the linear term.
 */
typedef struct secp256r1_keygen_shamir_polynomial {
    uint8_t generator_index;
    secp256r1_private_secret_scalar constant_term;
    secp256r1_private_secret_scalar linear_term;
} secp256r1_keygen_shamir_polynomial;

/** Share of the group secret key.
 *
 * The secret share results from evaluating the (generator) Shamir polynomial in the receiver index point.
 * For reference, these are the y_i_j values computed in KeyGen4 in the Utils_for_PoC.pdf file.
 */
typedef struct secp256r1_keygen_shamir_secret_share {
    uint8_t generator_index;
    uint8_t receiver_index;
    unsigned char value[32];
} secp256r1_keygen_shamir_secret_share;

/** Hash-based commitment scheme
 *
 * Commitment = H(nonce || value), where nonce is a fresh random 32-byte value
 * and value is the serialized representation of the committed data.
 * The hash function used is SHAKE_256.
 */
typedef struct secp256r1_commitment {
    unsigned char data[32];  // H(nonce || value)
} secp256r1_commitment;

/** Decommitment data for opening a commitment
 *
 * To verify a commitment, the recipient recomputes H(nonce || value)
 * and compares with the commitment.
 */
typedef struct secp256r1_decommitment {
    unsigned char nonce[32];                           // Random nonce
    unsigned char value[SECP256R1_MAX_COMMITMENT_SIZE]; // Could be an EC point or a scalar.
    uint8_t value_len;                                   // Actual length used
} secp256r1_decommitment;

/** Packet containing a commitment and the corresponding decommitment for a specific generator index.
 *
 * This packet is used to transmit both the commitment and the decommitment data for a specific generator index.
 * It contains:
 * - generator_index: The index of the generator associated with the commitment and decommitment.
 * - commitment: The hash-based commitment value.
 * - decommitment: The data required to open the commitment, including the nonce and the serialized value.
 */
typedef struct secp256r1_commitment_packet {
    uint8_t generator_index;
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
typedef struct secp256r1_nizkp {
    uint8_t generator_index;
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
typedef struct secp256r1_keygen_recovery_packet {
    uint8_t generator_index;
    unsigned char encrypted_y_3i[CIPHERTEXT_SIZE];
    unsigned char encrypted_y_i3[CIPHERTEXT_SIZE];
    secp256r1_nizkp nizkp_y_3i;
    secp256r1_nizkp nizkp_y_i3;
} secp256r1_keygen_recovery_packet;

/** Data structure containing all the recovery informations ready for serialization to be transmitted.
 */
typedef struct secp256r1_keygen_recovery_info {
    uint8_t generator_index;
    secp256r1_keygen_shamir_secret_share share_i_j;
    secp256r1_keygen_recovery_packet recovery_packet;
} secp256r1_keygen_recovery_info;

/** Data structure containing all the recovery informations
 * needed in the recovery signature phase ready for serialization to be transmitted to
 * the recovery party
 */
typedef struct secp256r1_signature_recovery_info {
    secp256r1_schnorr_pubkey pubkey;
    secp256r1_keygen_recovery_packet recovery_packet_1_3;
    secp256r1_keygen_recovery_packet recovery_packet_2_3;
} secp256r1_signature_recovery_info;

/** Schnorr's signature challenge e = H(m || R)
 *
 * This structure represents the challenge component of a Schnorr signature.
 */
typedef struct secp256r1_schnorr_hash_challenge {
    unsigned char value[16];
} secp256r1_schnorr_hash_challenge;

/** Schnorr's signature response s = r + e * x
 *
 * This structure represents the cumulative response component of a Schnorr signature.
 * Computed as the sum of the indexed responses s_i from all the signers, where each s_i is computed as s_i = r_i + e * x_i.
 */
typedef struct secp256r1_schnorr_response {
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
typedef struct secp256r1_schnorr_signature {
    unsigned char e[16];
    unsigned char s[32];
} secp256r1_schnorr_signature;

/** Context structure for the Schnorr key generation and signing protocol.
 *
 * This structure holds all the local data and intermediate values needed by a participant (Player I) during the execution of the Schnorr key generation and signing protocol.
 * It includes:
 * - RSA keys for encryption (assigned in Phase 2)
 * - Output of each phase of the key generation protocol, including secret scalars, public points, commitments, Shamir shares, NIZKPs, and recovery information.
 * - Parameters for control and state management during the protocol execution.
 */
typedef struct secp256r1_protocol_context{
    // Chiavi RSA (assegnate nella Phase 2)
    EVP_PKEY *rsa_pubkey;
    EVP_PKEY *rsa_privkey;

    // Output della Phase 1
    secp256r1_private_secret_scalar sec_scalar_array[2];
    secp256r1_keygen_shamir_secret_share sam_sec_share_y_3_i;
    secp256r1_point_extended ec_points_array[2];
    secp256r1_commitment_packet commitment_packets[2];
    CSPRNG_STATE_T csprng_state;

    // Output della Phase 2
    secp256r1_keygen_shamir_secret_share sam_sec_share_array[3]; // y_{i_1}, y_{i_2}, y_{i_3}
    secp256r1_point_extended M_i;                                // m_i * G
    secp256r1_keygen_recovery_packet recovery_packet;            // Packet per il recovery party

    //Output della Phase 3
    secp256r1_schnorr_seckey schnorr_seckey; // chiave privata omega per le firme Schnorr
    secp256r1_schnorr_reduced_shamir_shares schnorr_reduced_shares; // Shamir shares ridotti per la generazione della chiave privata Schnorr

    //Output della Phase 4
    secp256r1_schnorr_pubkey schnorr_pubkey; // chiave pubblica per le firme Schnorr
    secp256r1_point_extended A_3;

    //Output zkp
    secp256r1_point_extended h;
    secp256r1_private_secret_scalar nonce_r;
    secp256r1_point_extended u;
    secp256r1_private_secret_scalar nonce_c;
    secp256r1_private_secret_scalar z;

    secp256r1_point_extended h_other;
    secp256r1_point_extended u_other;
    secp256r1_private_secret_scalar nonce_c_other;
    secp256r1_private_secret_scalar z_other;


    //Output signature
    secp256r1_private_secret_scalar nonce_k;
    secp256r1_point_extended R_i;
    secp256r1_schnorr_hash_challenge e;
    secp256r1_private_secret_scalar s_i;
    secp256r1_schnorr_signature signature;
    secp256r1_commitment_packet s_commitment;
    secp256r1_commitment_packet r_commitment;

    unsigned char *message;
    uint8_t message_len;

    secp256r1_commitment_packet s_commitment_other;
    secp256r1_commitment_packet r_commitment_other;



    //Output recovery
    secp256r1_schnorr_seckey schnorr_seckey_recovery;
    secp256r1_private_secret_scalar a_3;
    secp256r1_keygen_shamir_secret_share shamir_share_recovery[4];
    secp256r1_schnorr_reduced_shamir_shares x_3;
    secp256r1_signature_recovery_info recovery_info;

    // Parametri di controllo locali
    uint8_t generator_index;

    //parametri di gestione di rete
    // (es. socket, indirizzi, buffer di ricezione, etc.)

} secp256r1_protocol_context;

/* ========================================================================
 * Key Generation API
 * ======================================================================== */

/** First phase of Schnorr key generation protocol.
 * Generates random values for {a_i, y_{3_i}, m_i} and the corresponding commitments.
 *
 * Returns: 0 if the arguments are invalid or the generation fails. 1 otherwise.
 * Args:
 * Out:     sec_scalar_array:   pointer to an array of secp256r1_private_secret_scalar structures
 *                              filled with a_i and m_i for each generator index.
 *          sam_sec_share:      pointer to a secp256r1_keygen_shamir_secret_share structure to be filled with y_3_i for the generator index.
 *          ec_points_array:    pointer to an array of secp256r1_point_extended structures
 *                              filled with the public points corresponding to a_i, y_{3_i} for each generator index.
 *          commitment_packets: pointer to an array of secp256r1_commitment_packet structures
 *                              filled with the generated commitments and decommitments.
 *          csprng_state:       pointer to a CSPRNG state structure to initialize with a seed for randomness generation.
 * In:      generator_index:    the index of the generator for which the key generation is being performed.
 *
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_phase1(
        secp256r1_private_secret_scalar *sec_scalar_array,
        secp256r1_keygen_shamir_secret_share *sam_sec_share,
        secp256r1_point_extended *ec_points_array,
        secp256r1_commitment_packet *commitment_packets,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Second phase of Schnorr key generation protocol.
 * Computes the Shamir secret shares and encrypts them for the receivers.
 *
 * Returns: 0 if the arguments are invalid or the generation fails. 1 otherwise.
 * Args:
 * Out:     sam_sec_share_array: pointer to an array of secp256r1_keygen_shamir_secret_share structures
 *                               filled with the evaluations of the Shamir polynomial.
 *                               The order will be: y_{i_1}, y_{i_2}, y_{i_3} for generator index i.
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
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_phase2(
        secp256r1_keygen_shamir_secret_share *sam_sec_share_array,
        secp256r1_point_extended *M_i,
        secp256r1_keygen_recovery_packet *recovery_packet,
        const secp256r1_private_secret_scalar *sec_scalar_array,
        const secp256r1_keygen_shamir_secret_share *sam_sec_share_y_3_i,
        const EVP_PKEY *enc_pubkey,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5) SECP256R1_ARG_NONNULL(6);

/** Compute and add the NIZKPs for the recovery packet of a specific generator index.
 * This function should be called after the recovery packet has been filled with the encrypted shares.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * In/Out: recovery_packet: pointer to a secp256r1_keygen_recovery_packet structure
 *                          to be filled with the NIZKPs for the generator index.
 *         sam_sec_share_array: pointer to an array of secp256r1_keygen_shamir_secret_share structures.
 *                          It contains y_{i_3} and y_{3_i} for the generator index.
 *  In:      csprng_state: pointer to a CSPRNG state structure initialized with a seed for randomness generation.
 *        generator_index: the index of the generator for which the NIZKPs are being computed.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_compute_nizkps(
        secp256r1_keygen_recovery_packet *recovery_packet,
        secp256r1_keygen_shamir_secret_share *sam_sec_share_array,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1);

/** Verify the NIZKPs for the recovery packet of a specific generator index.
 *
 * Returns: 0 if the arguments are invalid. -1 if the NIZKP does not verify. 1 otherwise.
 * Args:
 * In:      recovery_packet: pointer to a secp256r1_keygen_recovery_packet structure
 *                          containing the NIZKPs to verify for the generator index.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_verify_nizkps(
        const secp256r1_keygen_recovery_packet *recovery_packet
) SECP256R1_ARG_NONNULL(1);

/** Verify public shares correctness.
 * This function verifies that the public shares Y_{3_i} and M_i for a specific generator index
 * are correctly computed according to the Shamir polynomial.
 *
 * Returns: 0 if the arguments are invalid. -1 if the shares do not verify. 1 otherwise.
 * Args:
 * In:   y_j_i:              pointer to a secp256r1_secret_share structure containing the share y_{j_i} to verify.
 *       M_j:                pointer to a secp256r1_point_extended structure containing the public point M_j to verify.
 *       A_j:                pointer to a secp256r1_point_extended structure containing the public point A_j.
 *       generator_index:    the generator_index of the user which is verifying the shares.
 *                           I.e., to verify the shares from user 1, use generator_index = 2.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_verify_public_shares(
        const secp256r1_keygen_shamir_secret_share *y_j_i,
        const secp256r1_point_extended *M_j,
        const secp256r1_point_extended *A_j,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Generate the private key omega for Schnorr signatures.
 * This function computes the private key for Schnorr signatures for a specific generator index
 * from a reduction (sum) of secret shares of a Shamir polynomial
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     schnorr_seckey:   pointer to a secp256r1_schnorr_seckey structure to be filled
 *                           with the generated private key for the generator index.
 *          schnorr_seckey_rec: pointer to a secp256r1_schnorr_seckey structure to be filled
 *                              with the generated private key for the generator index to be used in the recovery phase.
 * In:      schnorr_reduced_shares: pointer to a secp256r1_schnorr_reduced_shamir_shares structure
 *          generator_index: the index of the generator for which the private key is being generated.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_generate_seckey(
        secp256r1_schnorr_seckey *schnorr_seckey,
        secp256r1_schnorr_seckey *schnorr_seckey_rec,
        const secp256r1_schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Reduces a set of Shamir secret shares into a secp256r1_reduced_shamir_shares structure.
 *
 * This function performes a scalar sum (modulo q) of the Shamir secret shares for a specific
 * generator i.
 *
 * Returns: 0 if the arguments are invalid or the computations fails. 1 otherwise.
 * Args:
 * Out:     schnorr_reduced_shares: pointer to a secp256r1_schnorr_reduced_shamir_shares structure
 *          to be filled with the reduced value.
 * In:      shamir_shares_arr:  pointer to an array of secp256r1_keygen_shamir_secret_share.
 *                              Filled with y_1_i, y_2_i and y_3_i for the generator index i.
 *          share_num:      number of shares to reduce
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_shamir_shares_reduction(
        secp256r1_schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        const secp256r1_keygen_shamir_secret_share *shamir_shares_arr,
        uint8_t share_num
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Initiates a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function generates the commitment u and the nonce r for the proof.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     u:               pointer to a secp256r1_point_extended structure to be filled
 *                           with the generated commitment R for the proof.
 *          r:               pointer to a secp256r1_private_secret_scalar to be filled with the generated nonce r for the proof.
 * In:      csprng_state:       pointer to a CSPRNG state structure initialized with a seed for randomness generation.
 *         generator_index: the index of the generator for which the proof is being generated.
 *
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_prove_knowledge(
        secp256r1_point_extended *u,
        secp256r1_private_secret_scalar *r,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Validates the commitment of a ZK proof and generates a random challenge for the proof.
 * This function checks that the commitment u is valid and generates a random challenge c for the proof.
 *
 * Returns: 0 if the arguments are invalid. -1 if the commitment is not verified. 1 otherwise.
 * Args:
 * Out:     c:               pointer to a 32-byte array to be filled with a random challenge for the proof.
 * In:      u:               pointer to a secp256r1_point_extended structure containing the commitment u for the proof.
 *          h:               pointer to a secp256r1_point_extended structure containing the point
 *                           h = G * x, where G is the generator of the curve and x is the secret scalar value to prove.
 *          csprng_state:       pointer to a CSPRNG state structure initialized with a seed for randomness generation.
 *          generator_index: the index of the generator for which the proof is being generated.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_generate_challenge(
        unsigned char *c,
        const secp256r1_point_extended *u,
        const secp256r1_point_extended *h,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Generates the response for a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function computes the response z for the proof using the nonce r and the challenge c.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     z:               pointer to a secp256r1_private_secret_scalar to be filled with the generated response for the proof.
 * In:      schnorr_seckey:  pointer to a secp256r1_schnorr_reduced_shamir_shares structure containing the secret key
 *                           for which the proof is being generated.
 *          c:               pointer to a secp256r1_private_secret_scalar containing the challenge c for the proof.
 *          r:               pointer to a secp256r1_private_secret_scalar containing the nonce r for the proof.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_generate_response(
        secp256r1_private_secret_scalar *z,
        const secp256r1_schnorr_reduced_shamir_shares *schnorr_seckey,
        const secp256r1_private_secret_scalar *c,
        const secp256r1_private_secret_scalar *r
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Validates a ZK proof of knowledge of the secret key corresponding to a Schnorr public key.
 * This function checks that the response z is valid for the given commitment u and challenge c.
 *
 * Returns: 0 if the arguments are invalid. -1 if the proof does not verify. 1 otherwise.
 * Args:
 * In:      h:              pointer to a secp256r1_point_extended structure containing the point corresponding to
 *                           the secret to prove.
 *          u:               pointer to a secp256r1_point_extended structure containing the commitment u for the proof.
 *          c:               pointer to a 32-byte array containing the challenge c for the proof.
 *          z:               pointer to a 32-byte array containing the response z for the proof.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_verify_proof(
        const secp256r1_point_extended *h,
        const secp256r1_point_extended *u,
        const secp256r1_private_secret_scalar *c,
        const secp256r1_private_secret_scalar *z
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Add a number of public keys together.
 *
 *  Returns: 1: the sum of the public keys is valid.
 *           0: the sum of the public keys is not valid.
 *  Args:
 *  Out:    out:        pointer to a public key object for placing the resulting public key.
 *  In:     ins:        pointer to array of secp256r1_schnorr_point_extended containing
 *                      the partial public keys to add.
 *          n:          the number of public keys to add together (must be at least 1).
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_combine(
        secp256r1_schnorr_pubkey *out,
        const secp256r1_point_extended *ins,
        uint8_t n
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Computes the recovery party public key A_3
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out/In:     A_3_schnorr_pubkey: pointer to a secp256r1_schnorr_point_extended structure
 *                                 to be filled with A_3.
 *             Y_shares_array:  pointer to an array of secp256r1_point_extended structures.
 *             It should contain the public shares Y_{3_1} and Y_{3_2}, in this order.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_A_3_compute(
        secp256r1_point_extended  *A_3_schnorr_pubkey,
        const secp256r1_point_extended *Y_shares_array
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/* ========================================================================
 * Ordinary Signature API
 * ======================================================================== */

/** First phase of Schnorr signing protocol.
 * Generates random value for r_i and the corresponding commitment.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     sec_scalar: pointer to a secp256r1_private_secret_scalar containing the scalar nonce k_i.
 *          r_i:                pointer to a secp256k1_point_extended structure to be filled with
 *                              the public point corresponding to r_i for the generator index.
 *          commitment_packet:  pointer to a secp256r1_commitment_packet structure filled with
 *                              the generated commitment and decommitment for r_i
 * In:      generator_index:    the index of the generator for which the signing is being performed.
 *         csprng_state:       pointer to a CSPRNG state structure initialized with a seed for randomness generation.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_sign_phase1(
        secp256r1_private_secret_scalar *sec_scalar,
        secp256r1_point_extended *r_i,
        secp256r1_commitment_packet *commitment_packet,
        uint8_t generator_index,
        CSPRNG_STATE_T *csprng_state
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(5);

/** Second phase of Schnorr signing protocol.
 * Computes the challenge e and the response s_i for a specific generator index.
 * Also returns the commitment-decommitment pair for s_i.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     schnorr_signature_chall:     pointer to a secp256r1_schnorr_hash_challenge.
 *          schnorr_signature_part_resp: pointer to a secp256r1_private_secret_scalar.
 *          commitment_packet:           pointer to a secp256r1_commitment_packet structure filled with
 *                                       the generated commitment and decommitment for s_i.
 * In:      schnorr_seckey:          pointer to a secp256r1_schnorr_seckey structure containing the secret key
 *                                   for which the signing is being performed.
 *          sec_scalar:              pointer to a secp256r1_private_secret_scalar structure containing the scalar nonce k_i for the generator index.
 *          message:                 pointer to the message being signed.
 *          message_len:             length of the message being signed.
 *          nonce:             pointer to a of secp256r1_point_extended structure containing the public nonce R.
 *          generator_index:         the index of the generator for which the signing is being performed.
 *          csprng_state:           pointer to a CSPRNG state structure initialized with a seed for randomness generation.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_sign_phase2(
        secp256r1_schnorr_hash_challenge *schnorr_signature_chall,
        secp256r1_private_secret_scalar *schnorr_signature_part_resp,
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_schnorr_seckey *schnorr_seckey,
        const secp256r1_private_secret_scalar *sec_scalar,
        const unsigned char *message,
        uint8_t message_len,
        const secp256r1_point_extended *nonce,
        uint8_t generator_index,
        CSPRNG_STATE_T *csprng_state
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4) SECP256R1_ARG_NONNULL(5) SECP256R1_ARG_NONNULL(6) SECP256R1_ARG_NONNULL(8);

/**
 * Combine partial Schnorr signature responses into a complete Schnorr signature.
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:
 * Out/In: sig48: pointer to a secp256r1_schnorr_signature in compact format (48 bytes) which is updated in place to contain the combined signature.
 *         partial_resps: pointer to an array of secp256r1_private_secret_scalar.
 *         n_partial_resps: the number of partial signatures in the partial_sigs array (must be at least 1).
 *         chall16: pointer to a secp256r1_hash_challenge containing the 16-byte challenge e for the signature.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_signature_combine(
        secp256r1_schnorr_signature *sig48,
        secp256r1_private_secret_scalar *partial_resps,
        uint8_t n_partial_resps,
        secp256r1_schnorr_hash_challenge *chall16
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(4);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           -1: incorrect signature
 *           0: computation error or invalid arguments
 *  Args:
 *  In:    sig48: pointer to a secp256r1_schnorr_signature structure.
 *           msg: the message being verified. Can only be NULL if msglen is 0.
 *        msglen: length of the message
 *        pubkey: pointer to a secp256r1_schnorr_pubkey structure containing the public key to verify against.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorrsig_verify(
        const secp256r1_schnorr_signature *sig48,
        const unsigned char *msg,
        uint8_t msglen,
        const secp256r1_schnorr_pubkey *pubkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(4);

/* ========================================================================
 * Recovery Signature API
 * ======================================================================== */

/** Generate the private key omega for Schnorr recovery signatures.
 * This function computes the private key for Schnorr signatures for a specific generator index
 * from a reduction (sum) of secret shares of a Shamir polynomial.
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out:     schnorr_seckey_rec:  pointer to a secp256r1_schnorr_seckey structure to be filled
 *                           with the generated private key for the generator index.
 * In:      schnorr_reduced_shares: pointer to a secp256r1_schnorr_reduced_shamir_shares structure
 *          generator_index: the index of the user requesting the recovery signature.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_keygen_generate_recovery_seckey(
        secp256r1_schnorr_seckey *schnorr_seckey_rec,
        const secp256r1_schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        uint8_t generator_index
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Computes the public key A_3 of the Recovery Party
 *
 * Returns: 0 if the arguments are invalid or the computation fails. 1 otherwise.
 * Args:
 * Out/In:  a_3_scalar: a pointer to a secp256r1_secret_scalar structure.
 *          A_3_pubkey: a pointer to a secp256r1_point_extended structure to be filled
 *                      with the computed EC point.
 * In:      shamir_share_arr:   a pointer to an array of secp256r1_keygen_shamir_secret_share.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_recovery_pubkey_share_gen(
        secp256r1_private_secret_scalar *a_3_scalar,
        secp256r1_point_extended *A_3_pubkey,
        const secp256r1_keygen_shamir_secret_share *shamir_share_arr
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Reduces a set of Shamir secret shares into a secp256r1_reduced_shamir_shares structure used by
 * the recovery party.
 *
 * This function performes a scalar sum (modulo q) of the Shamir secret shares
 * valid only for the recovery party.
 *
 * Returns: 0 if the arguments are invalid or the computations fails. 1 otherwise.
 * Args:
 * Out:     schnorr_reduced_shares: pointer to a secp256r1_schnorr_reduced_shamir_shares structure
 *          to be filled with the reduced value.
 * In:      shamir_shares_arr:  pointer to an array of secp256r1_keygen_shamir_secret_share
 *          share_num:      number of shares to reduce
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_shamir_shares_reduction_recovery(
        secp256r1_schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        const secp256r1_keygen_shamir_secret_share *shamir_shares_arr,
        uint8_t share_num
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/* ========================================================================
 * General Purpose API
 * ======================================================================== */

/** Verify a commitment-decommitment pair for a specific generator index.
 *
 * Returns: 0 if the arguments are invalid. -1 if the commitment does not match the decommitment.
 *          1 otherwise.
 * Args:
 * In:      commitment_packet:  pointer to a secp256r1_commitment_packet structure
 *                              containing the commitment and decommitment to verify.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_verify_commitment(
        const secp256r1_commitment_packet *commitment_packet
) SECP256R1_ARG_NONNULL(1);

/** Serialize a commitment to bytes.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer that will be filled with the serialized commitment (32 bytes)
 * In:      commit: pointer to the commitment
 */
int secp256r1_commitment_serialize(
        unsigned char *output,
        const secp256r1_commitment *commit
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a commitment from bytes
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     commit: pointer to the commitment structure to fill
 * In:      input: pointer to input buffer (32 bytes) containing the serialized commitment
 */
int secp256r1_commitment_parse(
        secp256r1_commitment *commit,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a decommitment to bytes for transmission.
 *
 * Format: [nonce(32)] + [value(value_len bytes)] + [value_len(4 bytes)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer, must be SECP256R1_DECOMMITMENT_BUFFER_SIZE bytes long
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 *          decommit: pointer to the decommitment
 */
int secp256r1_decommitment_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_decommitment *decommit
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Parse a decommitment from bytes received.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     decommit: pointer to the decommitment structure to fill
 * In:      input: pointer to input buffer, must be SECP256R1_DECOMMITMENT_BUFFER_SIZE bytes long
 *          input_len: length of input buffer in bytes
 */
int secp256r1_decommitment_parse(
        secp256r1_decommitment *decommit,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a recovery info structure to bytes for transmission.
 *
 * Format: [generator_index(1 byte)] + [shamir_share(34 bytes)] + [recovery_packet(fixed)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer, must be SECP256R1_RECOVERY_INFO_BUFFER_SIZE bytes long
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 *          recovery_info: pointer to the recovery info structure to serialize
 */
int secp256r1_keygen_recovery_info_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_keygen_recovery_info *recovery_info
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Parse a recovery info structure from bytes received.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     recovery_info: pointer to the recovery info structure to fill
 * In:      input: pointer to input buffer, must be SECP256R1_RECOVERY_INFO_BUFFER_SIZE bytes long
 *          input_len: must match SECP256R1_RECOVERY_INFO_BUFFER_SIZE
 */
int secp256r1_keygen_recovery_info_parse(
        secp256r1_keygen_recovery_info *recovery_info,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a signature recovery info structure to bytes for transmission.
 *
 * Format: [pubkey(66 bytes)] + [recovery_packet_1_3(fixed)] + [recovery_packet_2_3(fixed)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer, must be SECP256R1_SIGNATURE_RECOVERY_INFO_BUFFER_SIZE bytes long
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 * recovery_info: pointer to the signature recovery info structure to serialize
 */
int secp256r1_signature_recovery_info_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_signature_recovery_info *recovery_info
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Parse a signature recovery info structure from bytes received.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     recovery_info: pointer to the signature recovery info structure to fill
 * In:      input: pointer to input buffer, must be SECP256R1_SIGNATURE_RECOVERY_INFO_BUFFER_SIZE bytes long
 * input_len: length of input buffer in bytes, must match SECP256R1_SIGNATURE_RECOVERY_INFO_BUFFER_SIZE
 */
int secp256r1_signature_recovery_info_parse(
        secp256r1_signature_recovery_info *recovery_info,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a EC point in extended form to bytes for transmission.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer that will be filled with the serialized EC point.
 *                  Must be SECP256R1_POINT_EXTENDED_BUFFER_SIZE bytes long.
 * In:      point: pointer to the EC point to serialize
 */
int secp256r1_point_extended_serialize(
        unsigned char *output,
        const secp256r1_point_extended *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

 /** Parse a EC point in extended form from bytes received.
  * Returns: 1 on success, 0 on failure.
  * Out:     point: pointer to the EC point structure to fill
  * In:      input: pointer to input buffer containing the serialized EC point.
  *                 Must be SECP256R1_POINT_EXTENDED_BUFFER_SIZE bytes long.
  */
int secp256r1_point_extended_parse(
         secp256r1_point_extended *point,
         const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a private secret scalar to bytes for transmission.
*
* Format: [generator_index (1 byte)] || [value (32 bytes big-endian)]
*
* Returns: 1 on success, 0 on failure.
* Out:     output: pointer to output buffer. Must be 33 bytes long.
* In:      scalar: pointer to the scalar structure
*/
int secp256r1_private_scalar_serialize(
        unsigned char *output,
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a private secret scalar from bytes received from a peer.
 *
 * Format: [generator_index (1 byte)] || [value (32 bytes big-endian)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     scalar: pointer to the scalar structure to fill
 * In:      input: pointer to input buffer. Must be 33 bytes long
 */
int secp256r1_private_scalar_parse(
        secp256r1_private_secret_scalar *scalar,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Decrypt the encrypted shares in a recovery packet and fill an array of Shamir secret shares.
 *
 * Returns: 0 if the arguments are invalid or the decryption fails. 1 otherwise.
 * Args:
 * Out:     pubkey: pointer to a secp256r1_schnorr_pubkey structure containing the public key of the generator index for which the decryption is being performed.
 *          out_share_arr: pointer to an array of secp256r1_keygen_shamir_secret_share structures
 *                          to be filled with the decrypted shares for the generator index.
 * In:      recovery_info: pointer to a secp256r1_keygen_recovery_packet structure containing the encrypted shares to decrypt.
 *         enc_privkey: pointer to an RSA-3072 private key to use for decryption.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_recovery_info_decrypt(
        secp256r1_schnorr_pubkey *pubkey,
        secp256r1_keygen_shamir_secret_share *out_share_arr,
        const secp256r1_signature_recovery_info *recovery_info,
        EVP_PKEY *enc_privkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Collects a random seed in 32 bytes from the system
 * Returns: 1 on success, 0 on failure.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_collect_random_seed(
        unsigned char *seed
) SECP256R1_ARG_NONNULL(1);

#endif // SECP256R1_SCHNORR_H
