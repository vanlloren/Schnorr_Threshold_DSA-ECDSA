//
// Created by PC on 21/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H

#include "secp256r1_schnorr.h"

/** EC point in Jacobian coordinates.
 *
 * Represents a point on the secp256r1 curve in Jacobian coordinates,
 * which consist of three coordinates (X, Y, Z).
 *
 * The point is associated with a specific generator index.
 *
 * Little-endian representation is used for the coordinates:
 * the least significant byte is stored first.
 */
typedef struct secp256r1_point_gej {
    uint8_t generator_index;
    unsigned char X[32];
    unsigned char Y[32];
    unsigned char Z[32];
    int infinity; // flag to indicate if the point is at infinity
} secp256r1_point_gej;

/** EC point in affine coordinates.
 *
 * Represents a point on the secp256r1 curve in affine coordinates,
 * which consist of two coordinates (x, y).
 *
 * The point is associated with a specific generator index.
 *
 * Little-endian representation is used for the coordinates:
 * the least significant byte is stored first.
 */
typedef struct secp256r1_point_ge {
    uint8_t generator_index;
    unsigned char x[32];
    unsigned char y[32];
    int infinity; // flag to indicate if the point is at infinity
} secp256r1_point_ge;

/** Parse a point in Jacobian coordinates from a secp256r1_point_extended.
 *
 * Format: [generator_index (1 byte)] || [X (32 bytes big-endian)] || [Y (32 bytes big-endian)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     point: pointer to the EC point structure to fill
 * In:      input: pointer to the secp256r1_point_extended structure (65 bytes)
 */
int secp256r1_point_gej_parse(
        secp256r1_point_gej *point,
        secp256r1_point_extended *input
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2);

/** Serialize a point in Jacobian coordinates to a secp256r1_point_extended.
 *
 * Format: [generator_index (1 byte)] || [X (32 bytes big-endian)] || [Y (32 bytes big-endian)]
 *
 * Returns: 1 on success, 0 on failure.
 * Out:     output: pointer to the secp256r1_point_extended structure to fill
 * In:      point: pointer to the EC point structure (65 bytes)
 */
int secp256r1_point_gej_serialize(
        secp256r1_point_extended *output,
        const secp256r1_point_gej *point
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
int secp256r1_point_gej_scalar_mul(
        secp256r1_point_gej *result,
        const secp256r1_point_gej *point,
        const secp256r1_private_secret_scalar *scalar
) SECP256R1_ARG_NONNULL(1) SECP256R1_ARG_NONNULL(2) SECP256R1_ARG_NONNULL(3);

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_ECARITHMETICS_H
