//
// Created by PC on 21/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H

#include "secp256r1_schnorr.h"

#define SECP256R1_SCALAR_WORD_TYPE     uint32_t
#define SECP256R1_SCALAR_WORD_SIZE     32
#define SECP256R1_SCALAR_NUM_WORDS     (256 / SECP256R1_SCALAR_WORD_SIZE)

/** Data structure representing a scalar when performing operations.
 * This structure is used internally for performing scalar operations,
 * and is not intended to be used directly by users of the library.
 *
 * The scalar is represented as an array of 8 32-bit unsigned integers.
 * Little-endian format is used: the least significant word is stored in d[0]
 * and the most significant word is stored in d[7].
 */
typedef struct secp256r1_scalar_native {
    SECP256R1_SCALAR_WORD_TYPE d[SECP256R1_SCALAR_NUM_WORDS];
} secp256r1_scalar_native;

extern const secp256r1_scalar_native SECP256R1_Q_NATIVE;

#if defined(SECP256R1_SCALAR_WORD_TYPE) && defined(SECP256R1_SCALAR_NUM_WORDS)
#if SECP256R1_SCALAR_NUM_WORDS == 8
#define SECP256R1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}
#endif
#endif

/** Convert a byte array in big-endian format to a scalar in native format.
 *
 * The input array must be 32 bytes long (256 bits). The output scalar will be
 * represented using the internal word size defined by SECP256R1_SCALAR_WORD_TYPE.
 *
 * Returns: void.
 * Out: out: pointer to a secp256r1_scalar_native structure to be filled.
 * In:  in:  pointer to a buffer containing the 256-bit scalar in big-endian format.
 */
void bytes_to_scalar_native(
        secp256r1_scalar_native *out,
        const unsigned char *in
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Convert a scalar in native format to a byte array in big-endian format.
 *
 * Returns: void. The output array is filled with the big-endian representation of the scalar.
 * Out: out: pointer to a 32-byte array to be filled with the big-endian representation of the scalar.
 * In: in: pointer to a secp256r1_scalar_native structure containing the scalar in native format to convert.
 */
void scalar_native_to_bytes(
        unsigned char *out,
        const secp256r1_scalar_native *in
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Verify that a scalar in native format is valid (0 < scalar < n).
 *
 * Returns: 0 if the scalar is invalid. 1 otherwise.
 * Args:
 * In:     scalar: pointer to a secp256r1_scalar_native structure containing the scalar
 */
int secp256r1_scalar_verify_native(
        const secp256r1_scalar_native *scalar
) SECP256R1_ARG_NONNULL(1);

/** Serialize a scalar from native format to its public structure format for transmission.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     scalar_out: pointer to a secp256r1_private_secret_scalar structure to be
 *          filled with the serialized scalar.
 * In:      scalar_in: pointer to a secp256r1_scalar_native structure containing the scalar
 *          in native format to serialize.
 */
int secp256r1_scalar_native_serialize(
        secp256r1_private_secret_scalar *scalar_out,
        const secp256r1_scalar_native *scalar_in
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Parse a scalar from its public structure format to native format for performing operations.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     scalar_out: pointer to a secp256r1_scalar_native structure to be filled
 *          with the parsed scalar in native format.
 * In:      scalar_in: pointer to a secp256r1_private_secret_scalar structure containing the
 *          scalar in public structure format to parse.
 *          If the scalar is invalid according to secp256r1_schnorr_scalar_verify,
 *          this function returns 0 and scalar_in will be set to some unspecified value.
 */
int secp256r1_scalar_native_parse(
        secp256r1_scalar_native *scalar_out,
        const secp256r1_private_secret_scalar *scalar_in
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Verify that a scalar in public structure format is valid (0 < scalar < n).
 *
 * Returns: 0 if the scalar is invalid. 1 otherwise.
 * Args:
 * In:     scalar: pointer to a secp256r1_private_secret_scalar structure containing the scalar
 *                 to verify. If the scalar is invalid according to this function,
 */
int secp256r1_scalar_verify(
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1);

/** Add two scalar values together modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a secp256r1_private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar1: pointer to a secp256r1_private_secret_scalar containing the first scalar value.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar1 will be set to some unspecified value.
 *          scalar2: pointer to a secp256r1_private_secret_scalar containing the second scalar value.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar2 will be set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_add(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar1,
        const secp256r1_private_secret_scalar *scalar2
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Reduces a scalar value modulo the order of the curve.
 *
 * Returns: void. The input scalar is modified in place to contain the reduced value.
 * In: scalar: pointer to a secp256r1_scalar_native structure containing the scalar value to reduce.
 */
void scalar_reduce_mod_q(
        secp256r1_scalar_native *scalar
) SECP256R1_ARG_NONNULL(1);

/** Negates a scalar value modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a secp256r1_private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar: pointer to a secp256r1_private_secret_scalar containing the scalar value to negate.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar will be set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_negate(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Multiplies a scalar value by a constant modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a secp256r1_private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar: pointer to a secp256r1_private_secret_scalar containing the scalar value to multiply.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar will be set to some unspecified value.
 *          constant: uint32_t constant to multiply the scalar by. If the constant is zero, this function returns 0 and result is set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_mul_int(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar,
        uint8_t constant
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Multiplies a scalar value by another scalar value modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a secp256r1_private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar1: pointer to a secp256r1_private_secret_scalar containing the first scalar value.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar1 will be set to some unspecified value.
 *          scalar2: pointer to a secp256r1_private_secret_scalar containing the second scalar value.
 *                   If the scalar is invalid according to secp256r1_schnorr_scalar_verify, this
 *                  function returns 0 and scalar2 will be set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_mul(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar1,
        const secp256r1_private_secret_scalar *scalar2
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Verify that a scalar is valid
 *
 * (i.e., is in the range [1, n-1], where n is the order of the curve).
 *
 *  Returns: 0 if the scalar is invalid. 1 otherwise.
 *  Args:
 *  In:     scalar: pointer to a secp256r1_private_secret_scalar structure containing the scalar
 *                  to verify. If the scalar is invalid according to this function,
 *                  it is set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_verify(
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1);

/** Checks that a scalar equals zero.
 *
 * Returns: 0 if the scalar is not zero. 1 if the scalar is zero. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a secp256r1_private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to secp256r1_schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_is_zero(
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1);

/** Checks that a scalar equals one.
 *
 * Returns: 0 if the scalar is not one. 1 if the scalar is one. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a secp256r1_private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to secp256r1_schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_is_one(
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1);

/** Check that a scalar equals -1 (modulo the order of the curve).
 *
 * Returns: 0 if the scalar is not equal to -1. 1 if the scalar is equal to -1. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a secp256r1_private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to secp256r1_schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
SECP256R1_WARN_UNUSED_RESULT int secp256r1_scalar_is_neg_one(
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H