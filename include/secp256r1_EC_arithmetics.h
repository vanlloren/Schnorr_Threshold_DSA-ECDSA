//
// Created by PC on 21/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H

#include "secp256r1_schnorr.h"
#include "secp256r1_scalar_op.h"

typedef struct secp256r1_point_coord_native{
    SECP256R1_SCALAR_WORD_TYPE d[SECP256R1_SCALAR_NUM_WORDS];
} secp256r1_point_coord_native;

/** Values used in Montgomery multiplication.
 * These constants are precomputed for the specific modulus p of secp256r1.
 * They are used to perform efficient modular reduction in Montgomery form.
 */
#if (SECP256R1_SCALAR_WORD_SIZE == 32)
#define SECP256R1_P_PRIME_0 0x00000001
#define SECP256R1_P_WORDS \
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, \
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
#define SECP256R1_P_MINUS_2_WORDS \
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, \
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
#define SECP256R1_P_A_WORDS \
        0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, \
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
#define SECP256R1_P_R2_WORDS \
        0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB, \
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004
#define SECP256R1_P_A_MONTGOMERY_WORDS \
        0xFFFFFFFC, 0xFFFFFFFF, 0XFFFFFFFF, 0x00000003, \
        0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFC
#define SECP256R1_P_B_MONTGOMERY_WORDS \
        0x29C4BDDF, 0xD89CDF62, 0x78843090, 0xACF005CD, \
        0xF7212ED6, 0xE5A220AB, 0x04874834, 0xDC30061D
#define SECP256R1_P_R_MONTGOMERY_WORDS \
        0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, \
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000000
#elif (SECP256R1_SCALAR_WORD_SIZE == 64)
#define SECP256R1_P_PRIME 0x0000000000000001ULL
#define SECP256R1_P_WORDS \
        0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL, \
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
#define SECP256R1_P_MINUS_2_WORDS \
        0xFFFFFFFFFFFFFFFDULL, 0x00000000FFFFFFFFULL, \
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
#define SECP256R1_P_A \
        0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL, \
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
#define SECP256R1_P_R2_WORDS \
        0x0000000000000003ULL, 0xFFFFFFFBFFFFFFFFULL, \
        0xFFFFFFFF00000000ULL, 0x00000004FFFFFFFDULL
#define SECP256R1_P_A_MONTGOMERY_WORDS \
        0xFFFFFFFCFFFFFFFFULL, 0x0000000000000003ULL, \
        0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFCULL
#define SECP256R1_P_B_MONTGOMERY_WORDS \
        0xD89CDF62ACF005CDULL, 0xE5A220AB04874834ULL, \
        0xDC30061D29C4BDDFULL, 0xF7212ED6E5A220ABULL
#define SECP256R1_P_R_MONTGOMERY_WORDS \
        0x0000000000000001ULL, 0xFFFFFFFFFFFFFFFFULL, \
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
#endif

extern const secp256r1_point_coord_native SECP256R1_P_NATIVE;
extern const secp256r1_point_coord_native SECP256R1_P_PRIME_NATIVE;
extern const secp256r1_point_coord_native SECP256R1_P_R2_NATIVE;
extern const secp256r1_point_coord_native SECP256R1_P_ONE_NATIVE;
extern const secp256r1_point_coord_native SECP256R1_P_MINUS_2_NATIVE;
extern const secp256r1_point_coord_native SECP256R1_P_B_MONTGOMERY;
extern const secp256r1_point_coord_native SECP256R1_P_R_MONTGOMERY;
extern const secp256r1_point_coord_native SECP256R1_P_A_MONTGOMERY;
extern const secp256r1_point_coord_native SECP256R1_P_A;

/** EC point in Jacobian coordinates.
 *
 * Represents a point on the secp256r1 curve in Jacobian coordinates,
 * which consist of three coordinates (X, Y, Z).
 *
 * X, Y, and Z are represented in the Montgomery domain for efficient arithmetic operations.
 *
 * The point is associated with a specific generator index.
 *
 * Little-endian representation is used for the coordinates:
 * the least significant byte is stored first.
 */
typedef struct secp256r1_point_gej {
    uint8_t generator_index;
    secp256r1_point_coord_native X;
    secp256r1_point_coord_native Y;
    secp256r1_point_coord_native Z;
    int infinity; // flag to indicate if the point is at infinity
} secp256r1_point_gej;

/** EC point in affine coordinates.
 *
 * Represents a point on the secp256r1 curve in affine coordinates,
 * which consist of two coordinates (x, y).
 *
 * The point is associated with a specific generator index.
 * To represent the point at infinity, the 'infinity' flag is set to 1 and the coordinates are set to zero.
 *
 * Little-endian representation is used for the coordinates:
 * the least significant byte is stored first.
 */
typedef struct secp256r1_point_ge {
    uint8_t generator_index;
    secp256r1_point_coord_native x;
    secp256r1_point_coord_native y;
    int infinity; // flag to indicate if the point is at infinity
} secp256r1_point_ge;

/** Parse a point in affine coordinates from a secp256r1_point_extended.
 *
 * Source Format: [generator_index (1 byte)] || [X (32 bytes big-endian)] || [Y (32 bytes big-endian)]
 * In the destination structure, the coordinates are stored in little-endian format (least significant byte first).
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     point: pointer to the EC point structure to fill
 * In:      input: pointer to the secp256r1_point_extended structure (65 bytes)
 */
int secp256r1_point_ge_parse(
        secp256r1_point_ge *point,
        secp256r1_point_extended *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a point in affine coordinates to a secp256r1_point_extended.
 *
 * Destination Format: [generator_index (1 byte)] || [X (32 bytes big-endian)] || [Y (32 bytes big-endian)]
 * The source structure stores the coordinates in little-endian format (least significant byte first).
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to the secp256r1_point_extended structure to fill
 * In:      point: pointer to the EC point structure (65 bytes)
 */
int secp256r1_point_ge_serialize(
        secp256r1_point_extended *output,
        const secp256r1_point_ge *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Convert a point in affine coordinates to a jacobian point.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to the secp256r1_point_gej structure to fill
 * In:      point: pointer to the EC point structure
 */
int secp256r1_point_ge_to_gej(
        secp256r1_point_gej *output,
        const secp256r1_point_ge *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Normalize a point in affine coordinates from a jacobian point.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     point: pointer to the EC point structure to fill
 * In:      input: pointer to the secp256r1_point_gej structure
 */
int secp256r1_point_gej_to_ge(
        secp256r1_point_ge *point,
        const secp256r1_point_gej *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Check if a point in jacobian coordinates is at infinity.
 *
 * Returns: 1 if the point is at infinity, 0 otherwise.
 * In:      point: pointer to the EC point structure
 */
int secp256r1_point_gej_is_infinity(
        const secp256r1_point_gej *point
) SECP256R1_ARG_NONNULL(1);

/** Set a point in jacobian coordinates to infinity.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     point: pointer to the EC point structure to set to infinity
 */
int secp256r1_point_gej_set_infinity(
        secp256r1_point_gej *point
) SECP256R1_ARG_NONNULL(1);

/** Check if a point in jacobian coordinates is valid (i.e., on the curve).
 *
 * Returns: 1 if the point is valid, 0 otherwise.
 * In:      point: pointer to the EC point structure
 */
int secp256r1_point_gej_is_valid(
        const secp256r1_point_gej *point
) SECP256R1_ARG_NONNULL(1);

/** Checks if two points in jacobian coordinates are equal.
 *
 * Returns: 1 if the points are equal, 0 otherwise.
 * In:      point1: pointer to the first EC point structure
 *          point2: pointer to the second EC point structure
 */
int secp256r1_point_gej_equal(
        const secp256r1_point_gej *point1,
        const secp256r1_point_gej *point2
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Negate a point in jacobian coordinates.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill with the negated point
 * In:      point: pointer to the EC point structure to negate
 */
int secp256r1_point_gej_negate(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Add two points in jacobian coordinates.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill with the sum of the points
 * In:      point1: pointer to the first EC point structure
 *          point2: pointer to the second EC point structure
 */
int secp256r1_point_gej_add(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point1,
        const secp256r1_point_gej *point2
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Double a point in jacobian coordinates.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill with the doubled point
 * In:      point: pointer to the EC point structure to double
 */
int secp256r1_point_gej_double(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Add a point in jacobian coordinates with a point in affine coordinates.
 *
 * This is faster than gej_add when the second point is in affine coordinates.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill (in jacobian)
 * In:      point_jac: pointer to the point in jacobian coordinates
 *          point_aff: pointer to the point in affine coordinates
 */
int secp256r1_point_gej_add_ge(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point_jac,
        const secp256r1_point_ge *point_aff
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Multiply the generator G by a scalar.
 *
 * This is a specialized version of scalar multiplication that uses
 * precomputed tables for the generator, making it significantly faster.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill (in jacobian)
 * In:      scalar: pointer to the scalar to multiply the generator by
 */
int secp256r1_point_gej_scalar_mult_base(
        secp256r1_point_gej *result,
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Multiply a point in jacobian coordinates by a scalar.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     result: pointer to the EC point structure to fill with the resulting point
 * In:      point: pointer to the EC point structure to multiply
 *          scalar: pointer to the secp256r1_private_secret_scalar to multiply the point by
 */
int secp256r1_point_gej_scalar_mult(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point,
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

/** Perform Montgomery multiplication of two field elements in native format.
 *
 * Params:
 * Out:     result: pointer to the field element in native format to store the result
 * In:      a: pointer to the first field element in native format
 *         b: pointer to the second field element in native format
 *
 * Note: This function assumes that a and b are already in Montgomery form (i.e., multiplied by R mod p).
 * The result will also be in Montgomery form. To convert back to standard representation, multiply by 1 (R^-1 mod p).
 */
void secp256r1_field_p_montgomery_mul(
        secp256r1_point_coord_native *result,
        const secp256r1_point_coord_native *a,
        const secp256r1_point_coord_native *b
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H
