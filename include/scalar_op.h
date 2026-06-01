//
// Created by PC on 21/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H

#include "schnorr.h"

#if (SECURITY_LEVEL == 128)
#define SCALAR_TOTAL_BITS    256
#elif (SECURITY_LEVEL == 256)
#define SCALAR_TOTAL_BITS    576
#else
    #error "SECURITY_LEVEL non supportato! Scegliere 128 (per 256 bit) o 256 (per 521 bit)."
#endif


#if defined(USE_UINT64_WORDS) || (SCALAR_WORD_TYPE_SIZE == 64)
#define SCALAR_WORD_TYPE          uint64_t
    #define SCALAR_HALF_WORD_TYPE     uint32_t
    #define SCALAR_WORD_SIZE          64
#else
#define SCALAR_WORD_TYPE_SIZE 32
#define SCALAR_WORD_TYPE          uint32_t
#define SCALAR_HALF_WORD_TYPE     uint16_t
#define SCALAR_WORD_SIZE          32
#endif

#define SCALAR_NUM_WORDS     ((SCALAR_TOTAL_BITS + SCALAR_WORD_SIZE - 1) / SCALAR_WORD_SIZE)

/** Data structure representing a scalar when performing operations.
 * This structure is used internally for performing scalar operations,
 * and is not intended to be used directly by users of the library.
 *
 * The scalar is represented as an array of SCALAR_NUM_WORDS unsigned integers
 * (32 or 64 bytes depending on SCALAR_WORD_TYPE).
 *
 * Little-endian format is used: the least significant word is stored in d[0]
 * and the most significant word is stored in d[7].
 */
typedef struct scalar_native {
    SCALAR_WORD_TYPE d[SCALAR_NUM_WORDS];
} scalar_native;

/** Values used in Montgomery multiplication.
 * These constants are precomputed for the specific modulus q of secp256r1 (SECURITY_LEVEL == 128),
 * or for the modulus q of secp521r1 (SECURITY_LEVEL == 256).
 * They are used to perform efficient modular reduction in Montgomery form.
 */
#if (SECURITY_LEVEL == 128)
#if (SCALAR_WORD_SIZE == 32)
#define Q_PRIME_0 0xEE00BC4F
#define Q_WORDS \
        0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, \
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
#define ONE_WORDS \
        0x00000001, 0x00000000, 0x00000000, 0x00000000, \
        0x00000000, 0x00000000, 0x00000000, 0x00000000
#define R2_WORDS \
        0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C, \
        0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94
#elif (SCALAR_WORD_SIZE == 64)
#define Q_PRIME_0 0xCCD1C8AAEE00BC4FULL
#define Q_WORDS \
        0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL, \
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
#define ONE_WORDS \
        0x0000000000000001ULL, 0x0000000000000000ULL, \
        0x0000000000000000ULL, 0x0000000000000000ULL
#define R2_WORDS \
        0x83244C95BE79EEA2ULL, 0x4699799C49BD6FA6ULL, \
        0x2845B2392B6BEC59ULL, 0x66E12D94F3D95620ULL
#endif
#elif (SECURITY_LEVEL == 256)
#if (SCALAR_WORD_SIZE == 32)
#define Q_PRIME_0 0x79A995C7
#define Q_WORDS \
        0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, \
        0xf709a5d0, 0x7fcc0148, 0xbf2f966b, 0x51868783, \
        0xfffffffa, 0xFFFFFFFF, 0XFFFFFFFF, 0xFFFFFFFF, \
        0XFFFFFFFF, 0XFFFFFFFF, 0XFFFFFFFF, 0XFFFFFFFF, \
        0x000001FF, 0x00000000
#define ONE_WORDS \
        0x00000001, 0x00000000, 0x00000000, 0x00000000, \
        0x00000000, 0x00000000, 0x00000000, 0x00000000, \
        0x00000000, 0x00000000, 0x00000000, 0x00000000, \
        0x00000000, 0x00000000, 0x00000000, 0x00000000, \
        0x00000000, 0x00000000
#define R2_WORDS \
        0xcf15dd04, 0x137cd04d, 0xe5547ea3, 0xf707badc, \
        0x794573ff, 0x12a78d38, 0x57f75e06, 0xd3721ef5, \
        0x2e49c7db, 0xdd6e23d8, 0xb7756e3e, 0xcff3d142, \
        0xa8e567bc, 0x5bcc6d61, 0x492d0d45, 0x2d8e03d1, \
        0x0000003d, 0x00000000
#elif (SCALAR_WORD_SIZE == 64)
#define Q_PRIME_0 0x1d2f5CCD79A995C7ULL
#define Q_WORDS \
        0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b, \
        0xFFFFFFFFfffffffa, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0XFFFFFFFFFFFFFFFF, \
        0x00000000000001ff
#define ONE_WORDS \
        0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, \
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, \
        0x0000000000000000ULL
#define R2_WORDS \
        0x137cd04dcf15dd04, 0xf707badce5547ea3, 0x12a78d38794573ff, 0xd3721ef557f75e06, \
        0xdd6e23d82e49c7db, 0xcff3d142b7756e3e, 0x5bcc6d61a8e567bc, 0x2d8e03d1492d0d45, \
        0x000000000000003d
#endif
#endif

extern const scalar_native Q_NATIVE;
extern const scalar_native ONE_NATIVE;
extern const scalar_native R2_NATIVE;

#if defined(SCALAR_WORD_TYPE) && defined(SCALAR_NUM_WORDS)
#if SCALAR_NUM_WORDS == 18
/* Per secp521r1 su architetture a 32 bit */
        #define SCALAR_CONST(d17, d16, d15, d14, d13, d12, d11, d10, d9, d8, d7, d6, d5, d4, d3, d2, d1, d0) \
            {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7), (d8), (d9), (d10), (d11), (d12), (d13), (d14), (d15), (d16), (d17)}}

#elif SCALAR_NUM_WORDS == 9
/* Per secp521r1 su architetture a 64 bit */
        #define SCALAR_CONST(d8, d7, d6, d5, d4, d3, d2, d1, d0) \
            {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7), (d8)}}

#elif SCALAR_NUM_WORDS == 8
/* Per secp256r1 su architetture a 32 bit */
#define SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
            {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}

#elif SCALAR_NUM_WORDS == 4
/* Per secp256r1 su architetture a 64 bit */
        #define SCALAR_CONST(d3, d2, d1, d0) \
            {{(d0), (d1), (d2), (d3)}}
#endif
#endif

static inline SCALAR_WORD_TYPE mul_add_carry(
        SCALAR_WORD_TYPE a,
        SCALAR_WORD_TYPE b,
        SCALAR_WORD_TYPE c,
        SCALAR_WORD_TYPE *carry
) {
#if (SCALAR_WORD_SIZE == 64)
    /* Versione ottimizzata a 64-bit formalmente blindata */
    unsigned __int128 prod = (unsigned __int128)a * b;

    // Forziamo esplicitamente tutti gli elementi a essere a 128 bit prima della somma
    unsigned __int128 sum = prod + (unsigned __int128)c + (unsigned __int128)*carry;

    *carry = (SCALAR_WORD_TYPE)(sum >> 64);
    return (SCALAR_WORD_TYPE)sum;
#else
    SCALAR_WORD_TYPE a_lo = a & 0xFFFF, a_hi = a >> 16;
    SCALAR_WORD_TYPE b_lo = b & 0xFFFF, b_hi = b >> 16;
    SCALAR_WORD_TYPE c_lo = c & 0xFFFF, c_hi = c >> 16;
    SCALAR_WORD_TYPE cy_lo = (*carry) & 0xFFFF, cy_hi = (*carry) >> 16;

    SCALAR_WORD_TYPE p0 = a_lo * b_lo;
    SCALAR_WORD_TYPE p1 = a_lo * b_hi;
    SCALAR_WORD_TYPE p2 = a_hi * b_lo;
    SCALAR_WORD_TYPE p3 = a_hi * b_hi;

    SCALAR_WORD_TYPE col0 = (p0 & 0xFFFF) + c_lo + cy_lo;
    SCALAR_HALF_WORD_TYPE out0 = (SCALAR_HALF_WORD_TYPE)(col0 & 0xFFFF);
    SCALAR_WORD_TYPE cry0 = col0 >> 16;

    SCALAR_WORD_TYPE col1 = (p0 >> 16) + (p1 & 0xFFFF) + (p2 & 0xFFFF) + c_hi + cy_hi + cry0;
    SCALAR_HALF_WORD_TYPE out1 = (SCALAR_HALF_WORD_TYPE)(col1 & 0xFFFF);
    SCALAR_WORD_TYPE cry1 = col1 >> 16;

    SCALAR_WORD_TYPE col2 = (p1 >> 16) + (p2 >> 16) + (p3 & 0xFFFF) + cry1;
    SCALAR_HALF_WORD_TYPE out2 = (SCALAR_HALF_WORD_TYPE)(col2 & 0xFFFF);
    SCALAR_WORD_TYPE cry2 = col2 >> 16;

    SCALAR_WORD_TYPE col3 = (p3 >> 16) + cry2;
    SCALAR_HALF_WORD_TYPE out3 = (SCALAR_HALF_WORD_TYPE)(col3 & 0xFFFF);

    *carry = ((SCALAR_WORD_TYPE)out3 << 16) | (SCALAR_WORD_TYPE)out2;
    return ((SCALAR_WORD_TYPE)out1 << 16) | (SCALAR_WORD_TYPE)out0;
#endif
}

/** Convert a byte array in big-endian format to a scalar in native format.
 *
 * The input array must be 32 or 66 bytes long (256 or 521 bits). The output scalar will be
 * represented using the internal word size defined by SCALAR_WORD_TYPE.
 *
 * Returns: void.
 * Out: out: pointer to a scalar_native structure to be filled.
 * In:  in:  pointer to a buffer containing the scalar in big-endian format.
 */
void bytes_to_scalar_native(
        scalar_native *out,
        const unsigned char *in
) ARG_NONNULL(1) ARG_NONNULL(2);

/** Convert a scalar in native format to a byte array in big-endian format.
 *
 * Returns: void. The output array is filled with the big-endian representation of the scalar.
 * Out: out: pointer to an array to be filled with the big-endian representation of the scalar.
 * In: in: pointer to a scalar_native structure containing the scalar in native format to convert.
 */
void scalar_native_to_bytes(
        unsigned char *out,
        const scalar_native *in
) ARG_NONNULL(1) ARG_NONNULL(2);

/** Verify that a scalar in native format is valid (0 < scalar < n).
 *
 * Returns: 0 if the scalar is invalid. 1 otherwise.
 * Args:
 * In:     scalar: pointer to a scalar_native structure containing the scalar
 */
int scalar_verify_native(
        const scalar_native *scalar
) ARG_NONNULL(1);

/** Serialize a scalar from native format to its public structure format for transmission.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     scalar_out: pointer to a private_secret_scalar structure to be
 *          filled with the serialized scalar.
 * In:      scalar_in: pointer to a scalar_native structure containing the scalar
 *          in native format to serialize.
 */
int scalar_native_serialize(
        private_secret_scalar *scalar_out,
        const scalar_native *scalar_in
) ARG_NONNULL(1) ARG_NONNULL(2);

/** Parse a scalar from its public structure format to native format for performing operations.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     scalar_out: pointer to a scalar_native structure to be filled
 *          with the parsed scalar in native format.
 * In:      scalar_in: pointer to a private_secret_scalar structure containing the
 *          scalar in public structure format to parse.
 *          If the scalar is invalid according to schnorr_scalar_verify,
 *          this function returns 0 and scalar_in will be set to some unspecified value.
 */
int scalar_native_parse(
        scalar_native *scalar_out,
        const private_secret_scalar *scalar_in
) ARG_NONNULL(1) ARG_NONNULL(2);

/** Verify that a scalar in public structure format is valid (0 < scalar < n).
 *
 * Returns: 0 if the scalar is invalid. 1 otherwise.
 * Args:
 * In:     scalar: pointer to a private_secret_scalar structure containing the scalar
 *                 to verify. If the scalar is invalid according to this function,
 */
int scalar_verify(
        const private_secret_scalar *scalar
) ARG_NONNULL(1);

/** Add two scalar values together modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar1: pointer to a private_secret_scalar containing the first scalar value.
 *                   If the scalar is invalid according to schnorr_scalar_verify, this
 *                  function returns 0 and scalar1 will be set to some unspecified value.
 *          scalar2: pointer to a private_secret_scalar containing the second scalar value.
 *                   If the scalar is invalid according to schnorr_scalar_verify, this
 *                  function returns 0 and scalar2 will be set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_add(
        private_secret_scalar *result,
        const private_secret_scalar *scalar1,
        const private_secret_scalar *scalar2
) ARG_NONNULL(1) ARG_NONNULL(2) ARG_NONNULL(3);

/** Reduces a scalar value modulo the order of the curve.
 *
 * Returns: void. The input scalar is modified in place to contain the reduced value.
 * In: scalar: pointer to a scalar_native structure containing the scalar value to reduce.
 */
void scalar_reduce_mod_q(
        scalar_native *scalar
) ARG_NONNULL(1);

/** Negates a scalar value modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar: pointer to a private_secret_scalar containing the scalar value to negate.
 *                   If the scalar is invalid according to schnorr_scalar_verify, this
 *                  function returns 0 and scalar will be set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_negate(
        private_secret_scalar *result,
        const private_secret_scalar *scalar
) ARG_NONNULL(1) ARG_NONNULL(2);

/** Performs Montgomery multiplication of two scalars in native format.
 *
 */
void montgomery_mul(
        scalar_native *result,
        const scalar_native *a,
        const scalar_native *b
) ARG_NONNULL(1) ARG_NONNULL(2) ARG_NONNULL(3);

/** Multiplies a scalar value by another scalar value modulo the order of the curve.
 *
 * Returns: 0 if the arguments are invalid or the resulting scalar would be zero. 1 otherwise.
 * Out:     result: pointer to a private_secret_scalar to be filled with the resulting scalar.
 * In:      scalar1: pointer to a private_secret_scalar containing the first scalar value.
 *                   If the scalar is invalid according to schnorr_scalar_verify, this
 *                  function returns 0 and scalar1 will be set to some unspecified value.
 *          scalar2: pointer to a private_secret_scalar containing the second scalar value.
 *                   If the scalar is invalid according to schnorr_scalar_verify, this
 *                  function returns 0 and scalar2 will be set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_mult(
        private_secret_scalar *result,
        const private_secret_scalar *scalar1,
        const private_secret_scalar *scalar2
) ARG_NONNULL(1) ARG_NONNULL(2) ARG_NONNULL(3);

/** Verify that a scalar is valid
 *
 * (i.e., is in the range [1, n-1], where n is the order of the curve).
 *
 *  Returns: 0 if the scalar is invalid. 1 otherwise.
 *  Args:
 *  In:     scalar: pointer to a private_secret_scalar structure containing the scalar
 *                  to verify. If the scalar is invalid according to this function,
 *                  it is set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_verify(
        const private_secret_scalar *scalar
) ARG_NONNULL(1);

/** Checks that a scalar equals zero.
 *
 * Returns: 0 if the scalar is not zero. 1 if the scalar is zero. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_is_zero(
        const private_secret_scalar *scalar
) ARG_NONNULL(1);

/** Checks that a scalar equals one.
 *
 * Returns: 0 if the scalar is not one. 1 if the scalar is one. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a _private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_is_one(
        const private_secret_scalar *scalar
) ARG_NONNULL(1);

/** Check that a scalar equals -1 (modulo the order of the curve).
 *
 * Returns: 0 if the scalar is not equal to -1. 1 if the scalar is equal to -1. -1 if the scalar is invalid.
 * Args:
 * In:      scalar: pointer to a private_secret_scalar structure containing the scalar
 *                  to check. If the scalar is invalid according to schnorr_scalar_verify,
 *                  this function returns -1 and scalar is set to some unspecified value.
 */
WARN_UNUSED_RESULT int scalar_is_neg_one(
        const private_secret_scalar *scalar
) ARG_NONNULL(1);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_SCALAROP_H