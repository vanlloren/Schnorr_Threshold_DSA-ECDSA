//
// Created by PC on 09/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H

#include <stddef.h>
#include <secp256r1_schnorr.h>

/** Parse a variable-length public key into the pubkey object.
 *
 *  Returns: 1 if the public key was fully valid.
 *           0 if the public key could not be parsed or is invalid.
 *  Args: ctx:      pointer to a context object.
 *  Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
 *                  parsed version of input. If not, its value is undefined.
 *  In:   input:    pointer to a serialized public key
 *        inputlen: length of the array pointed to by input
 *
 *  This function supports parsing compressed (33 bytes, header byte 0x02 or
 *  0x03) or uncompressed (65 bytes, header byte 0x04) format public keys.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_parse(
        secp256r1_schnorr_pubkey *pubkey,
        const unsigned char *input,
        uint32_t inputlen
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Serialize a pubkey object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        pointer to a context object.
 *  Out:    output:     pointer to a 65-byte (if compressed==0) or 33-byte (if
 *                      compressed==1) byte array to place the serialized key
 *                      in.
 *  In/Out: outputlen:  pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     pubkey:     pointer to a secp256r1_schnorr_pubkey containing an
 *                      initialized public key.
 *          flags:      SECP256R1_EC_COMPRESSED if serialization should be in
 *                      compressed format, otherwise SECP256R1_EC_UNCOMPRESSED.
 */
SECP256R1_API int secp256R1_schnorr_pubkey_serialize(
        const secp256r1_context *ctx,
        unsigned char *output,
        uint32_t *outputlen,
        const secp256r1_schnorr_pubkey *pubkey,
        unsigned int flags
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Compare two public keys using lexicographic (of compressed serialization) order
 *
 *  Returns: <0 if the first public key is less than the second
 *           >0 if the first public key is greater than the second
 *           0 if the two public keys are equal
 *  Args: ctx:      pointer to a context object
 *  In:   pubkey1:  first public key to compare
 *        pubkey2:  second public key to compare
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_cmp(
        const secp256r1_context *ctx,
        const secp256r1_schnorr_pubkey *pubkey1,
        const secp256r1_schnorr_pubkey *pubkey2
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Sort public keys using lexicographic (of compressed serialization) order
 *
 *  Returns: 0 if the arguments are invalid. 1 otherwise.
 *
 *  Args:     ctx: pointer to a context object
 *  In:   pubkeys: array of pointers to pubkeys to sort
 *      n_pubkeys: number of elements in the pubkeys array
 */
SECP256R1_API int secp256R1_schnorr_pubkey_sort(
        const secp256r1_context *ctx,
        const secp256r1_schnorr_pubkey **pubkeys,
        uint32_t n_pubkeys
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a Schnorr signature in compact (48 bytes) format.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args: ctx:      pointer to a context object
 *  Out:  sig:      pointer to a signature object
 *  In:   input48:  pointer to the 48-byte array to parse
 *
 *  The signature must consist of a 16-byte big endian e value, followed by a
 *  32-byte big endian S value. If e or S fall outside of [0..order-1], the
 *  encoding is invalid. e and S with value 0 are allowed in the encoding.
 *
 *  After the call, sig will always be initialized. If parsing failed or e or
 *  S are zero, the resulting sig value is guaranteed to fail verification for
 *  any message and public key.
 */
SECP256R1_API int secp256r1_schnorr_signature_parse_compact(
        const secp256r1_context *ctx,
        secp256r1_schnorr_signature *sig,
        const unsigned char *input48
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Serialize a Schnorr signature in compact (48 byte) format.
 *
 *  Returns: 1
 *  Args:   ctx:       pointer to a context object
 *  Out:    output48:  pointer to a 48-byte array to store the compact serialization
 *  In:     sig:       pointer to an initialized signature object
 *
 *  See secp256r1_schnorr_signature_parse_compact for details about the encoding.
 */
SECP256R1_API int secp256r1_schnorr_signature_serialize_compact(
        const secp256r1_context *ctx,
        unsigned char *output48,
        const secp256r1_schnorr_signature *sig
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx: pointer to a context object.
 *  In:    sig48: pointer to a secp256r1_schnorr_signature structure.
 *           msg: the message being verified. Can only be NULL if msglen is 0.
 *        msglen: length of the message
 *        pubkey: pointer to a secp256r1_schnorr_pubkey structure containing the public key to verify against.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorrsig_verify(
        const secp256r1_context *ctx,
        const secp256r1_schnorr_signature *sig48,
        const unsigned char *msg,
        uint32_t msglen,
        const secp256r1_xonly_pubkey *pubkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(5);

/** Verify a schnorr elliptic curve secret key.
 *
 *  A secret key is valid if it is not 0 and less than the secp256r1 curve order
 *  when interpreted as an integer (most significant byte first). The
 *  probability of choosing a 32-byte string uniformly at random which is an
 *  invalid secret key is negligible. However, if it does happen it should
 *  be assumed that the randomness source is severely broken and there should
 *  be no retry.
 *
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  Args:    ctx: pointer to a context object.
 *  In:      seckey: pointer to a 32-byte secret key.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_seckey_verify(
        const secp256r1_context *ctx,
        const unsigned char *seckey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Negates a secret key.
 *
 *  Returns: 0 if the given secret key is invalid according to
 *           secp256r1_schnorr_seckey_verify. 1 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    negseckey:  pointer to a 32-byte array to be filled with the negated secret key.
 *                      If 0 is returned, it is set to some unspecified value.
 *  In:     seckey:     pointer to the 32-byte secret key to be negated. If the
 *                      secret key is invalid according to
 *                      secp256k1_schnorr_seckey_verify, this function returns 0 and
 *                      seckey will be set to some unspecified value.
 *
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_seckey_negate(
        const secp256k1_context *ctx,
        unsigned char *negseckey,
        unsigned char *seckey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Negates a public key.
 *
 *  Returns: 1 always
 *  Args:   ctx:        pointer to a context object
 *  Out:    negpubkey:  pointer to a pubkey object to be filled with the negated public key.
 *  In:     pubkey:     pointer to the public key to be negated.
 */
SECP256R1_API int secp256r1_schnorr_pubkey_negate(
        const secp256r1_context *ctx,
        secp256r1_schnorr_pubkey *negpubkey,
        secp256r1_schnorr_pubkey *pubkey
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Tweak a secret key by adding tweak to it.
 *
 *  Returns:                0 if the arguments are invalid or the resulting secret key would be
 *                          invalid (only when the tweak is the negation of the secret key). 1
 *                          otherwise.
 *  Args:    ctx:           pointer to a context object.
 *  Out:     tweakseckey:   pointer to a 32-byte array to be filled with the tweaked secret key.
 *  In:      seckey:        pointer to a 32-byte secret key. If the secret key is
 *                          invalid according to secp256r1_schnorr_seckey_verify, this
 *                          function returns 0. seckey will be set to some unspecified
 *                          value if this function returns 0.
 *           tweak32:       pointer to a 32-byte tweak, which must be valid according to
 *                          secp256r1_schnorr_seckey_verify or 32 zero bytes. For uniformly
 *                          random 32-byte tweaks, the chance of being invalid is
 *                          negligible (around 1 in 2^128).
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_seckey_tweak_add(
        const secp256r1_context *ctx,
        unsigned char *tweakseckey,
        unsigned char *seckey,
        const unsigned char *tweak32
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Tweak a public key by adding tweak times the generator to it.
 *
 *  Returns: 0 if the arguments are invalid or the resulting public key would be
 *           invalid (only when the tweak is the negation of the corresponding
 *           secret key). 1 otherwise.
 *  Args:    ctx:   pointer to a context object.
 *  Out:    tweakpubkey: pointer to a pubkey object to be filled with the tweaked public key.
 *                      if 0 is returned, it is set to some unspecified value.
 *  In: pubkey: pointer to a public key object. pubkey will be set to an
 *                  invalid value if this function returns 0.
 *      tweak32: pointer to a 32-byte tweak, which must be valid according to
 *                  secp256r1_schnorr_seckey_verify or 32 zero bytes. For uniformly
 *                  random 32-byte tweaks, the chance of being invalid is
 *                  negligible (around 1 in 2^128).
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_tweak_add(
        const secp256r1_context *ctx,
        secp256r1_schnorr_pubkey *tweakpubkey,
        secp256r1_schnorr_pubkey *pubkey,
        const unsigned char *tweak32
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Tweak a secret key by multiplying it by a tweak.
 *
 *  Returns: 0 if the arguments are invalid. 1 otherwise.
 *  Args:   ctx:    pointer to a context object.
 *  Out: tweakseckey: pointer to a 32-byte array to be filled with the tweaked secret key.
 *                    If 0 is returned, it is set to some unspecified value.
 *  In: seckey:     pointer to a 32-byte secret key. If the secret key is
 *                  invalid according to secp256r1_schnorr_seckey_verify, this
 *                  function returns 0. seckey will be set to some unspecified
 *                  value if this function returns 0.
 *          tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
 *                  secp256r1_schnorr_seckey_verify, this function returns 0. For
 *                  uniformly random 32-byte arrays the chance of being invalid
 *                  is negligible (around 1 in 2^128).
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_seckey_tweak_mul(
        const secp256r1_context *ctx,
        unsigned char *tweakseckey,
        unsigned char *seckey,
        const unsigned char *tweak32
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Tweak a public key by multiplying it by a tweak value.
 *
 *  Returns: 0 if the arguments are invalid. 1 otherwise.
 *  Args:    ctx:   pointer to a context object.
 *  Out: tweakpubkey: pointer to a pubkey object to be filled with the tweaked public key.
 *                    If 0 is returned, it is set to some unspecified value.
 *  In: pubkey: pointer to a public key object. pubkey will be set to an
 *                  invalid value if this function returns 0.
 *      tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
 *                  secp256r1_schnorr_seckey_verify, this function returns 0. For
 *                  uniformly random 32-byte arrays the chance of being invalid
 *                  is negligible (around 1 in 2^128).
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_pubkey_tweak_mul(
        const secp256r1_context *ctx,
        secp256r1_schnorr_pubkey *tweakpubkey,
        secp256r1_schnorr_pubkey *pubkey,
        const unsigned char *tweak32
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(4);

/** Add a number of public keys together.
 *
 *  Returns: 1: the sum of the public keys is valid.
 *           0: the sum of the public keys is not valid.
 *  Args:   ctx:        pointer to a context object.
 *  Out:    out:        pointer to a public key object for placing the resulting public key.
 *  In:     ins:        pointer to array of pointers to public keys.
 *          n:          the number of public keys to add together (must be at least 1).
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256R1_schnorr_pubkey_combine(
        const secp256r1_context *ctx,
        secp256r1_schnorr_pubkey *out,
        const secp256r1_schnorr_pubkey * const *ins,
        uint32_t n
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Verify a commitment-decommitment pair for a specific generator index.
 *
 * Returns: 0 if the arguments are invalid or the commitment does not match the decommitment. 1 otherwise.
 * Args:    ctx:                pointer to a context object.
 * In:      commitment_packet:  pointer to a secp256r1_commitment_packet structure
 *                              containing the commitment and decommitment to verify.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_verify_commitment(
        const secp256r1_context *ctx,
        const secp256r1_commitment_packet *commitment_packet
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/**
 * Combine partial Schnorr signature responses into a complete Schnorr signature.
 * Returns: 0 if the arguments are invalid. 1 otherwise.
 * Args:    ctx:                pointer to a context object.
 * Out/In: sig48: pointer to a secp256r1_schnorr_signature in compact format (48 bytes) which is updated in place to contain the combined signature.
 *         partial_resps: pointer to an array of secp256r1_schnorr_response.
 *         n_partial_resps: the number of partial signatures in the partial_sigs array (must be at least 1).
 *         chall16: pointer to a secp256r1_hash_challenge containing the 16-byte challenge e for the signature.
 */
SECP256R1_API SECP256R1_WARN_UNUSED_RESULT int secp256r1_schnorr_signature_combine(
        const secp256r1_context *ctx,
        secp256r1_schnorr_signature *sig48,
        secp256r1_schnorr_response *partial_resps,
        uint32_t n_partial_resps,
        secp256r1_schnorr_hash_challenge *chall16
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3) SECP256R1_ARG_NONNULL(5);

/** Serialize a commitment to bytes.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer that will be filled with the serialized commitment (32 bytes)
 * In:      commit: pointer to the commitment
 */
SECP256R1_API int secp256r1_commitment_serialize(
        unsigned char *output,
        const secp256r1_commitment *commit
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a commitment from bytes
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     commit: pointer to the commitment structure to fill
 * In:      input: pointer to input buffer (32 bytes) containing the serialized commitment
 */
SECP256R1_API int secp256r1_commitment_parse(
        secp256r1_commitment *commit,
        const unsigned char *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a decommitment to bytes for transmission.
 *
 * Format: [nonce(32)] + [value(value_len bytes)] + [value_len(32 bytes)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 *          decommit: pointer to the decommitment
 */
SECP256R1_API int secp256r1_decommitment_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_decommitment *decommit
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Parse a decommitment from bytes received.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     decommit: pointer to the decommitment structure to fill
 * In:      input: pointer to input buffer
 *          input_len: length of input buffer in bytes
 */
SECP256R1_API int secp256r1_decommitment_parse(
        secp256r1_decommitment *decommit,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a nizkp to bytes for transmission.
 *
 * Format: [u(65 bytes)] + [c(32 bytes)] + [z(32 bytes)] + [h(65 bytes)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to output buffer
 * In:      output_len: pointer to an integer which is initially set to the size of output, and is overwritten with the written size
 *          nizkp: pointer to the nizkp structure to serialize
 */
SECP256R1_API int secp256r1_nizkp_serialize(
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
SECP256R1_API int secp256r1_nizkp_parse(
        secp256r1_nizkp *nizkp,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/**
 * Serialize a recovery packet to bytes for transmission.
 *
 * Format:
 * [generator_index (32 bytes)] +
 * [encrypted_y_3i (RSA3072_CIPHERTEXT_SIZE bytes)] +
 * [encrypted_y_i3 (RSA3072_CIPHERTEXT_SIZE bytes)] +
 * [nizkp_y_3i (serialized)] +
 * [nizkp_y_i3 (serialized)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output:     pointer to output buffer
 * In:      output_len: pointer to uint32_t - input: buffer size, output: bytes written
 *          packet:     pointer to the recovery packet to serialize
 */
SECP256R1_API int secp256r1_recovery_packet_serialize(
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
SECP256R1_API int secp256r1_recovery_packet_parse(
        secp256r1_keygen_recovery_packet *packet,
        const unsigned char *input,
        uint32_t input_len
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_GPAPI_H
