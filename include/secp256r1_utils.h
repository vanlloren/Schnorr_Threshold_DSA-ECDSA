//
// Created by PC on 09/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H

#include <stddef.h>
#include <secp256r1_schnorr.h>
#include "sha3.h"

#define HASH_DIGEST_LENGTH 32

/* ========================================================================
 * Internal Serialization API
 * ======================================================================== */

/** Serialize a nizkp to bytes for transmission.
 *
 * Format: [u(65 bytes)] + [c(32 bytes)] + [z(32 bytes)] + [h(65 bytes)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 *          nizkp: pointer to the nizkp structure to serialize
 */
int secp256r1_nizkp_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_nizkp *nizkp
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Parse a nizkp from bytes received.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     nizkp: pointer to the nizkp structure to fill
 * In:      input: pointer to input buffer
 *          input_len: length of input buffer in bytes
 */
int secp256r1_nizkp_parse(
        secp256r1_nizkp *nizkp,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/**
 * Serialize a recovery packet to bytes for transmission.
 *
 * Format:
 * [generator_index (1 byte)] +
 * [encrypted_y_3i (CIPHERTEXT_SIZE bytes)] +
 * [encrypted_y_i3 (CIPHERTEXT_SIZE bytes)] +
 * [nizkp_y_3i (to serialize)] +
 * [nizkp_y_i3 (to serialize)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output:     pointer to output buffer
 * In:      output_len: pointer to uint32_t - input: buffer size, output: bytes written
 *          packet:     pointer to the recovery packet to serialize
 */
int secp256r1_recovery_packet_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_keygen_recovery_packet *packet
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/**
 * Parse a recovery packet from bytes received from a peer.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     packet:     pointer to the recovery packet structure to fill
 * In:      input:      pointer to input buffer
 *          input_len:  length of input buffer in bytes
 */
int secp256r1_recovery_packet_parse(
        secp256r1_keygen_recovery_packet *packet,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a Shamir secret share to bytes for transmission.
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer that will be filled with the serialized Shamir secret share (33 bytes)
 * In:      share: pointer to the Shamir secret share to serialize
 */
int secp256r1_keygen_shamir_secret_share_serialize(
        unsigned char *output,
        const secp256r1_keygen_shamir_secret_share *share
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a Shamir secret share from bytes received.
* Returns: 1 on success, 0 on failure.
* Out:     share: pointer to the Shamir secret share structure to fill
* In:      input: pointer to input buffer (33 bytes) containing the serialized Shamir secret share
*/
int secp256r1_keygen_shamir_secret_share_parse(
        secp256r1_keygen_shamir_secret_share *share,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a variable-length public key into the pubkey object.
*
*  Returns: 1 if the public key was fully valid.
*           0 if the public key could not be parsed or is invalid.
*  Args:
*  Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
*                  parsed version of input. If not, its value is undefined.
*  In:   input:    pointer to a serialized public key
*        inputlen: length of the array pointed to by input
*
*  This function supports parsing uncompressed (65 bytes, header byte 0x04) format public keys.
*/
SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_parse(
        secp256r1_schnorr_pubkey *pubkey,
        const unsigned char *input,
        uint8_t inputlen
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Serialize a pubkey object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *  Args:
 *  Out:    output:     pointer to a 65-byte array to place the serialized key
 *                      in.
 *  In/Out: outputlen:  pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     pubkey:     pointer to a secp256r1_schnorr_pubkey containing an
 *                      initialized public key.
 */
int secp256R1_schnorr_pubkey_serialize(
        unsigned char *output,
        uint8_t *outputlen,
        const secp256r1_schnorr_pubkey *pubkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/* ========================================================================
 * Hash Functions
 * ======================================================================== */

/* Opaque algorithm agnostic hash call */
static inline
void hash(uint8_t digest[HASH_DIGEST_LENGTH],
          const unsigned char *const m,
          const uint64_t mlen,
          const uint16_t dsc){
    /* SHAKE with a 2*lambda bit digest is employed also for hashing */
    CSPRNG_STATE_T csprng_state;
    xof_shake_init(&csprng_state);
    xof_shake_update(&csprng_state,m,mlen);
    uint8_t dsc_ordered[2];
    dsc_ordered[0] = dsc & 0xff;
    dsc_ordered[1] = (dsc >> 8) & 0xff;
    xof_shake_update(&csprng_state,dsc_ordered,2);
    xof_shake_final(&csprng_state);
    xof_shake_extract(&csprng_state,digest,HASH_DIGEST_LENGTH);
}

/* ========================================================================
 * Commitment API
 * ======================================================================== */

/** Generate commitment and decommitment for a given EC point.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     commitment_packet: pointer to a secp256r1_commitment_packet structure to be filled with the generated commitment and decommitment.
 * In:      point: pointer to a secp256r1_point_extended for which
 *                 to generate the commitment and decommitment.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_commit_point(
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_point_extended *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Generate commitment and decommitment for a given secp256r1_schnorr_response
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     commitment_packet: pointer to a secp256r1_commitment_packet structure to be filled with the generated commitment and decommitment.
 * In:      response: pointer to a secp256r1_schnorr_response for which
 *                to generate the commitment and decommitment.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_commit_response(
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_schnorr_response *response
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H
