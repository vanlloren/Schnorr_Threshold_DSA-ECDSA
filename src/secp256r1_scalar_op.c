//
// Created by PC on 05/05/2026.
//

/* ========================================================================
 * FILE: secp256r1_scalar_op.c
 * ========================================================================
 * Implementation of scalar operations for secp256r1.
 * ========================================================================
 */

#include "secp256r1_scalar_op.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

const secp256r1_scalar_native SECP256R1_Q_NATIVE = { { SECP256R1_Q_WORDS } };
const secp256r1_scalar_native SECP256R1_ONE_NATIVE = { { SECP256R1_ONE_WORDS } };
const secp256r1_scalar_native SECP256R1_R2_NATIVE = { { SECP256R1_R2_WORDS } };



/* ========================================================================
 * Utility functions for endianness conversion
 * ======================================================================== */

void bytes_to_scalar_native(secp256r1_scalar_native *out, const unsigned char *in) {
    const int bytes_per_word = SECP256R1_SCALAR_WORD_SIZE / 8;

    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        out->d[i] = 0;
        for (int j = 0; j < bytes_per_word; j++) {
            /*
            * Index explanation:
            * 31 is the last byte of the array (LSB in Big-Endian).
            * (i * bytes_per_word) moves us to the correct word.
            * j moves us within the word.
            */
            int byte_idx = 31 - (i * bytes_per_word) - j;
            out->d[i] |= ((SECP256R1_SCALAR_WORD_TYPE)in[byte_idx] << (8 * j));
        }
    }
}

void scalar_native_to_bytes(unsigned char *out, const secp256r1_scalar_native *in) {
    const int bytes_per_word = SECP256R1_SCALAR_WORD_SIZE / 8;

    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        for (int j = 0; j < bytes_per_word; j++) {
            /*
            * Index calculation:
            * We start from the end of the array (31) since it's Big-Endian.
            * Subtract the space occupied by previous words (i * bytes_per_word).
            * Subtract the offset of the current byte within the word (j).
            */
            int byte_idx = 31 - (i * bytes_per_word) - j;

            /*
            * Extract the j-th byte from the i-th word.
            * Shift right by 0, 8, 16, 24... bits and mask to isolate the byte.
             */
            out[byte_idx] = (unsigned char)((in->d[i] >> (8 * j)) & 0xFF);
        }
    }
}

/* ========================================================================
 * Scalar verification (native format)
 * ======================================================================== */

int secp256r1_scalar_verify_native(const secp256r1_scalar_native *scalar) {
    int is_zero = 1;

    /* Check if scalar is zero by iterating through all words */
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (scalar->d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;  /* Scalar cannot be zero in this context */
    }

    /*
     * Check if scalar < Q (the order of the curve).
     * We compare words starting from the Most Significant Word (MSW).
     */
    for (int i = SECP256R1_SCALAR_NUM_WORDS - 1; i >= 0; i--) {
        if (scalar->d[i] > SECP256R1_Q_NATIVE.d[i]) {
            return 0; /* Scalar is greater than Q */
        } else if (scalar->d[i] < SECP256R1_Q_NATIVE.d[i]) {
            return 1; /* Scalar is strictly less than Q */
        }
        /* If words are equal, continue to the next less significant word */
    }

    /* If we reach here, scalar is exactly equal to Q, which is invalid */
    return 0;
}

/* ========================================================================
 * Public API: Serialization and Parsing
 * ======================================================================== */

int secp256r1_scalar_native_serialize(
        secp256r1_private_secret_scalar *scalar_out,
        const secp256r1_scalar_native *scalar_in
) {
    if (scalar_out == NULL || scalar_in == NULL) {
        return 0;
    }

    /* Verify the scalar is valid before serialization */
    if (!secp256r1_scalar_verify_native(scalar_in)) {
        return 0;
    }

    /* Convert from native format to bytes */
    scalar_native_to_bytes(scalar_out->value, scalar_in);

    /* Set the generator index from the scalar (if needed) */
    /* For base scalars, index is 0; for shares, index should be set by caller */
    scalar_out->generator_index = 0;

    return 1;
}

int secp256r1_scalar_native_parse(
        secp256r1_scalar_native *scalar_out,
        const secp256r1_private_secret_scalar *scalar_in
) {
    if (scalar_out == NULL || scalar_in == NULL) {
        return 0;
    }

    /* Convert from bytes to native format using the generalized helper */
    bytes_to_scalar_native(scalar_out, scalar_in->value);

    /* Verify the parsed scalar is valid (0 < scalar < Q) */
    if (!secp256r1_scalar_verify_native(scalar_out)) {
        /*
         * Set to an unspecified value on failure.
         * We zero out all words using the generalized macro.
         */
        for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
            scalar_out->d[i] = 0;
        }
        return 0;
    }

    return 1;
}

/* ========================================================================
 * Additional helper functions for the rest of the API
 * ======================================================================== */

int secp256r1_scalar_verify(const secp256r1_private_secret_scalar *scalar) {
    secp256r1_scalar_native native;

    if (scalar == NULL) {
        return 0;
    }

    /* Parse and verify */
    return secp256r1_scalar_native_parse(&native, scalar);
}

int secp256r1_scalar_is_zero(const secp256r1_private_secret_scalar *scalar) {
    secp256r1_scalar_native native;
    int i;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar */
    if (!secp256r1_scalar_native_parse(&native, scalar)) {
        /* Check if all words are zero */
        for (i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
            if (native.d[i] != 0) {
                return -1; /* Invalid scalar, not zero */
            }
        }
        return 1;  /* Invalid scalar, is a zero */
    }

    return 0;
}

int secp256r1_scalar_is_one(const secp256r1_private_secret_scalar *scalar) {
    secp256r1_scalar_native native;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar into native format */
    if (!secp256r1_scalar_native_parse(&native, scalar)) {
        return -1;  /* Invalid scalar according to curve order */
    }

    /*
     * Check if the scalar equals 1.
     * The least significant word (d[0]) must be 1,
     * and all other words must be 0.
     */
    if (native.d[0] != 1) {
        return 0;
    }

    for (int i = 1; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (native.d[i] != 0) {
            return 0; /* Not one */
        }
    }

    return 1; /* Scalar is exactly one */
}

int secp256r1_scalar_is_neg_one(const secp256r1_private_secret_scalar *scalar) {
    secp256r1_scalar_native native;
    int i;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar */
    if (!secp256r1_scalar_native_parse(&native, scalar)) {
        return -1;  /* Invalid scalar */
    }

    /* Check if the scalar equals n-1 (negative one) */
    for (i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (native.d[i] != SECP256R1_Q_NATIVE.d[i] - (i == 0 ? 1 : 0)) {
            return 0;
        }
    }

    return 1;
}

/* ========================================================================
 * Helper: Reduce a scalar modulo q (the order of the curve)
 * ======================================================================== */

void scalar_reduce_mod_q(secp256r1_scalar_native *scalar) {
    int ge = 0;

    /* Check if scalar >= Q by comparing words from Most Significant to Least */
    for (int i = SECP256R1_SCALAR_NUM_WORDS - 1; i >= 0; i--) {
        if (scalar->d[i] > SECP256R1_Q_NATIVE.d[i]) {
            ge = 1;
            break;
        } else if (scalar->d[i] < SECP256R1_Q_NATIVE.d[i]) {
            ge = 0;
            break;
        }
        /* If all words are equal, it's also >= Q */
        if (i == 0) {
            ge = 1;
        }
    }

    if (ge) {
        SECP256R1_SCALAR_WORD_TYPE borrow = 0;

        /* Multiple Precision Subtraction (Algorithm 1.2)  */
        for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {

            /* Step 6 & 7: (A_i - B_i) mod b and (x_i - k_in) mod b  */
            SECP256R1_SCALAR_WORD_TYPE diff = scalar->d[i] - SECP256R1_Q_NATIVE.d[i];
            SECP256R1_SCALAR_WORD_TYPE res = diff - borrow;

            /* Step 8: k_out = (x_i > A_i) + (tmp > x_i)
             * In C, a comparison evaluates to 1 if true, 0 otherwise. */
            borrow = (diff > scalar->d[i]) + (res > diff);

            /* Step 9: Save the result digit  */
            scalar->d[i] = res;
        }
    }
}

/* ========================================================================
 * Implementation of scalar addition (using helper)
 * ======================================================================== */

int secp256r1_scalar_add(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar1,
        const secp256r1_private_secret_scalar *scalar2
) {
    secp256r1_scalar_native native1, native2, native_result;
    SECP256R1_SCALAR_WORD_TYPE k_out = 0;

    /* Validate input parameters */
    if (result == NULL || scalar1 == NULL || scalar2 == NULL) {
        return 0;
    }

    /* Parse scalars to native format (validates 0 < scalar < Q) */
    if (!secp256r1_scalar_native_parse(&native1, scalar1)) {
        return 0;
    }
    if (!secp256r1_scalar_native_parse(&native2, scalar2)) {
        return 0;
    }

    /* * Perform Multiple Precision Addition (Algorithm 1.1)
     * This replaces 64-bit casts with logical carry detection.
     */
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        /* Step 6: x_i = (A_i + B_i) mod b [cite: 27] */
        SECP256R1_SCALAR_WORD_TYPE sum_words = native1.d[i] + native2.d[i];

        /* Step 7: tmp = (x_i + k_in) mod b [cite: 27] */
        SECP256R1_SCALAR_WORD_TYPE tmp = sum_words + k_out;

        /* * Step 8: k_out = (x_i < A_i) + (tmp < x_i)
         * Carry detection based on the property that a sum with carry
         * is lower than its addends[cite: 27, 28, 35].
         */
        k_out = (sum_words < native1.d[i]) + (tmp < sum_words);

        /* Step 9: Final digit assignment [cite: 27] */
        native_result.d[i] = tmp;
    }

    /* * Handle final carry or modular reduction.
     * If k_out (x_n) is 1, the result is >= R > Q[cite: 27, 154].
     */
    if (k_out) {
        SECP256R1_SCALAR_WORD_TYPE borrow = 0;
        for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
            SECP256R1_SCALAR_WORD_TYPE a_i = native_result.d[i];
            SECP256R1_SCALAR_WORD_TYPE b_i = SECP256R1_Q_NATIVE.d[i];
            SECP256R1_SCALAR_WORD_TYPE diff = a_i - b_i;
            SECP256R1_SCALAR_WORD_TYPE res = diff - borrow;
            borrow = (diff > a_i) + (res > diff);
            native_result.d[i] = res;
        }
    } else {
        /* Even without a final carry, result might still be >= Q */
        scalar_reduce_mod_q(&native_result);
    }

    /* Check if result is zero (not allowed for secret scalars) */
    int is_zero = 1;
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (native_result.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;
    }

    /* Serialize result back to public format */
    if (!secp256r1_scalar_native_serialize(result, &native_result)) {
        return 0;
    }

    return 1;
}

int secp256r1_scalar_negate(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar
) {
    secp256r1_scalar_native native, negated;
    SECP256R1_SCALAR_WORD_TYPE borrow = 0;

    /* Validate input parameters */
    if (result == NULL || scalar == NULL) {
        return 0;
    }

    /* Parse scalar to native format (validates 0 < scalar < Q) */
    if (!secp256r1_scalar_native_parse(&native, scalar)) {
        return 0;
    }

    /* * Negate the scalar: negated = Q - native.
     * Implementation based on Multiple Precision Subtraction (Algorithm 1.2).
     */
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        SECP256R1_SCALAR_WORD_TYPE a = SECP256R1_Q_NATIVE.d[i];
        SECP256R1_SCALAR_WORD_TYPE b = native.d[i];

        /* Compute the result word including the previous borrow */
        SECP256R1_SCALAR_WORD_TYPE res = a - b - borrow;

        /* * Step 8: Safe and robust branchless borrow detection.
         * A borrow occurs if:
         * 1) b is strictly greater than a (immediate underflow)
         * 2) a equals b AND a previous borrow was active (forcing underflow)
         * Using logical OR (||) strictly constrains 'borrow' to 0 or 1.
         */
        borrow = (a < b) || (a == b && borrow);

        /* Step 9: Save the result digit */
        negated.d[i] = res;
    }

    /* * Check if negated result is zero.
     * Note: Since 0 < native < Q, then 0 < negated < Q.
     * The result can only be zero if the input was zero, which is
     * already filtered by secp256r1_scalar_native_parse.
     */
    int is_zero = 1;
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (negated.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;  /* Result cannot be zero for secret scalar */
    }

    /* Serialize negated result to public format */
    if (!secp256r1_scalar_native_serialize(result, &negated)) {
        return 0;
    }

    return 1;
}

void secp256r1_montgomery_mul(
        secp256r1_scalar_native *result,
        const secp256r1_scalar_native *a,
        const secp256r1_scalar_native *b
) {
    /* Accumulatore x con limb extra per il carry finale (8 + 1 = 9 words) */
    SECP256R1_SCALAR_WORD_TYPE x[SECP256R1_SCALAR_NUM_WORDS + 1] = {0};

    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        /* 1. Moltiplicazione-Accumulo della riga: x = x + a[i]*b */
        SECP256R1_SCALAR_WORD_TYPE carry1 = 0;
        for (int j = 0; j < SECP256R1_SCALAR_NUM_WORDS; j++) {
            x[j] = mul_add_carry(a->d[i], b->d[j], x[j], &carry1);
        }

        /* Gestione del carry che eccede i 256 bit durante la moltiplicazione */
        SECP256R1_SCALAR_WORD_TYPE x_n_prev = x[SECP256R1_SCALAR_NUM_WORDS];
        SECP256R1_SCALAR_WORD_TYPE x_n_new = x_n_prev + carry1;
        SECP256R1_SCALAR_WORD_TYPE carry_n = (x_n_new < x_n_prev) ? 1 : 0;

        /* 2. Calcolo fattore di riduzione Montgomery per questa riga */
        SECP256R1_SCALAR_WORD_TYPE t = x[0] * SECP256R1_Q_PRIME_0;

        /* 3. Riduzione (passaggio di Montgomery): x = (x + t*Q) / b */
        SECP256R1_SCALAR_WORD_TYPE carry2 = 0;
        /* La prima operazione annulla x[0], quindi shiftiamo i risultati di un indice */
        mul_add_carry(t, SECP256R1_Q_NATIVE.d[0], x[0], &carry2);

        for (int j = 1; j < SECP256R1_SCALAR_NUM_WORDS; j++) {
            x[j - 1] = mul_add_carry(t, SECP256R1_Q_NATIVE.d[j], x[j], &carry2);
        }

        /* 4. Consolidamento dei carry finali e completamento dello shift */
        SECP256R1_SCALAR_WORD_TYPE sum_low = x_n_new + carry2;
        SECP256R1_SCALAR_WORD_TYPE sum_high = (sum_low < x_n_new) ? 1 : 0;
        sum_high += carry_n;

        x[SECP256R1_SCALAR_NUM_WORDS - 1] = sum_low;
        x[SECP256R1_SCALAR_NUM_WORDS] = sum_high;
    }

    /* 5. Riduzione Finale Condizionale (x = x >= Q ? x - Q : x) */
    SECP256R1_SCALAR_WORD_TYPE borrow = 0;
    secp256r1_scalar_native temp_res;

    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        SECP256R1_SCALAR_WORD_TYPE a_i = x[i];
        SECP256R1_SCALAR_WORD_TYPE b_i = SECP256R1_Q_NATIVE.d[i];

        SECP256R1_SCALAR_WORD_TYPE diff = a_i - b_i - borrow;

        /* Calcolo borrow senza cast */
        if (borrow == 0) {
            borrow = (a_i < b_i) ? 1 : 0;
        } else {
            borrow = (a_i <= b_i) ? 1 : 0;
        }

        temp_res.d[i] = diff;
    }

    SECP256R1_SCALAR_WORD_TYPE x_n = x[SECP256R1_SCALAR_NUM_WORDS];

    /* Decisione basata sul carry extra (x_n) e sul borrow della sottrazione */
    if (x_n == 1 || borrow == 0) {
        *result = temp_res;
    } else {
        for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
            result->d[i] = x[i];
        }
    }
}

int secp256r1_scalar_mult(
        secp256r1_private_secret_scalar *result,
        const secp256r1_private_secret_scalar *scalar1,
        const secp256r1_private_secret_scalar *scalar2
) {
    secp256r1_scalar_native native1, native2, product;

    /* Parameter validation */
    if (result == NULL || scalar1 == NULL || scalar2 == NULL) {
        return 0;
    }

    /* Parse scalars to native format (validates 0 < scalar < Q) */
    if (!secp256r1_scalar_native_parse(&native1, scalar1)) {
        return 0;
    }
    if (!secp256r1_scalar_native_parse(&native2, scalar2)) {
        return 0;
    }

    /* Convert native scalars into Montgomery form for efficient multiplication */
    secp256r1_scalar_native native1_tilde, native2_tilde;

    secp256r1_montgomery_mul(&native1_tilde, &native1, &SECP256R1_R2_NATIVE);
    secp256r1_montgomery_mul(&native2_tilde, &native2, &SECP256R1_R2_NATIVE);

    /* Perform Montgomery multiplication: product_tilde = native1_tilde * native2_tilde * R^-1 mod Q */
    secp256r1_scalar_native product_tilde;
    secp256r1_montgomery_mul(&product_tilde, &native1_tilde, &native2_tilde);

    /* Convert product back from Montgomery form to standard representation */
    secp256r1_montgomery_mul(&product, &product_tilde, &SECP256R1_ONE_NATIVE);

    /* Check if product is zero (not allowed for secret scalars) */
    int is_zero = 1;
    for (int i = 0; i < SECP256R1_SCALAR_NUM_WORDS; i++) {
        if (product.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;  /* Result cannot be zero for secret scalar */
    }

    /* Serialize product back to public format */
    if (!secp256r1_scalar_native_serialize(result, &product)) {
        return 0;
    }

    return 1;
}
