//
// Created by PC on 05/05/2026.
//

/* ========================================================================
 * FILE: secp256r1_scalar_op.c
 * ========================================================================
 * Implementation of scalar operations for secp256r1.
 * ========================================================================
 */

#include "scalar_op.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

const scalar_native Q_NATIVE = { { Q_WORDS } };
const scalar_native ONE_NATIVE = { { ONE_WORDS } };
const scalar_native R2_NATIVE = { { R2_WORDS } };

/* ========================================================================
 * Utility functions for endianness conversion
 * ======================================================================== */
void bytes_to_scalar_native(scalar_native *out, const unsigned char *in) {
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;

    // 1. Puliamo interamente la struttura di output.
    // Questo garantisce che eventuali byte di padding iniziale (es. nelle 17 word di secp521r1)
    // rimangano impostati a 0 in modo sicuro.
    memset(out, 0, sizeof(scalar_native));

    // 2. Iteriamo sulle word native del sistema
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        for (int j = 0; j < bytes_per_word; j++) {

            // Calcoliamo l'offset logico del byte partendo dal fondo (LSB)
            int total_byte_offset = (i * bytes_per_word) + j;

            // Verifichiamo di non superare la dimensione reale dei byte in input
            if (total_byte_offset < SCALAR_SIZE) {
                int byte_idx = (SCALAR_SIZE - 1) - total_byte_offset;
                out->d[i] |= ((SCALAR_WORD_TYPE)in[byte_idx] << (8 * j));
            }
        }
    }
}

void scalar_native_to_bytes(unsigned char *out, const scalar_native *in) {
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;

    // 1. Inizializziamo il buffer di output esterno a zero.
    // Questo è fondamentale per pulire in sicurezza i byte iniziali (MSB)
    // se lo spazio nativo delle word è leggermente più grande dei byte serializzati richiesti.
    memset(out, 0, SCALAR_SIZE);

    // 2. Iteriamo sulle word native del sistema
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        for (int j = 0; j < bytes_per_word; j++) {

            // Calcoliamo l'offset logico del byte partendo dal fondo (dall'unita meno significativa)
            int total_byte_offset = (i * bytes_per_word) + j;

            // Esportiamo il byte solo se rientra nella dimensione effettiva del buffer serializzato
            if (total_byte_offset < SCALAR_SIZE) {
                int byte_idx = (SCALAR_SIZE - 1) - total_byte_offset;

                /*
                * Extract the j-th byte from the i-th word.
                * Shift right by 0, 8, 16, 24... bits and mask to isolate the byte.
                */
                out[byte_idx] = (unsigned char)((in->d[i] >> (8 * j)) & 0xFF);
            }
        }
    }
}

/* ========================================================================
 * Scalar verification (native format)
 * ======================================================================== */

int scalar_verify_native(const scalar_native *scalar) {
    int is_zero = 1;

    /* Check if scalar is zero by iterating through all words */
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
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
    for (int i = SCALAR_NUM_WORDS - 1; i >= 0; i--) {
        if (scalar->d[i] > Q_NATIVE.d[i]) {
            return 0; /* Scalar is greater than Q */
        } else if (scalar->d[i] < Q_NATIVE.d[i]) {
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

int scalar_native_serialize(
        private_secret_scalar *scalar_out,
        const scalar_native *scalar_in
) {
    if (scalar_out == NULL || scalar_in == NULL) {
        return 0;
    }

    /* Verify the scalar is valid before serialization */
    if (!scalar_verify_native(scalar_in)) {
        return 0;
    }

    /* Convert from native format to bytes */
    scalar_native_to_bytes(scalar_out->value, scalar_in);

    /* Set the generator index from the scalar (if needed) */
    /* For base scalars, index is 0; for shares, index should be set by caller */
    scalar_out->generator_index = 0;

    return 1;
}

int scalar_native_parse(
        scalar_native *scalar_out,
        const private_secret_scalar *scalar_in
) {
    if (scalar_out == NULL || scalar_in == NULL) {
        return 0;
    }

    /* Convert from bytes to native format using the generalized helper */
    bytes_to_scalar_native(scalar_out, scalar_in->value);

    /* Verify the parsed scalar is valid (0 < scalar < Q) */
    if (!scalar_verify_native(scalar_out)) {
        /*
         * Set to an unspecified value on failure.
         * We zero out all words using the generalized macro.
         */
        for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
            scalar_out->d[i] = 0;
        }
        return 0;
    }

    return 1;
}

/* ========================================================================
 * Additional helper functions for the rest of the API
 * ======================================================================== */

int scalar_verify(const private_secret_scalar *scalar) {
    scalar_native native;

    if (scalar == NULL) {
        return 0;
    }

    /* Parse and verify */
    return scalar_native_parse(&native, scalar);
}

int scalar_is_zero(const private_secret_scalar *scalar) {
    scalar_native native;
    int i;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar */
    if (!scalar_native_parse(&native, scalar)) {
        /* Check if all words are zero */
        for (i = 0; i < SCALAR_NUM_WORDS; i++) {
            if (native.d[i] != 0) {
                return -1; /* Invalid scalar, not zero */
            }
        }
        return 1;  /* Invalid scalar, is a zero */
    }

    return 0;
}

int scalar_is_one(const private_secret_scalar *scalar) {
    scalar_native native;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar into native format */
    if (!scalar_native_parse(&native, scalar)) {
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

    for (int i = 1; i < SCALAR_NUM_WORDS; i++) {
        if (native.d[i] != 0) {
            return 0; /* Not one */
        }
    }

    return 1; /* Scalar is exactly one */
}

int scalar_is_neg_one(const private_secret_scalar *scalar) {
    scalar_native native;
    int i;

    if (scalar == NULL) {
        return -1;
    }

    /* Parse the scalar */
    if (!scalar_native_parse(&native, scalar)) {
        return -1;  /* Invalid scalar */
    }

    /* Check if the scalar equals n-1 (negative one) */
    for (i = 0; i < SCALAR_NUM_WORDS; i++) {
        if (native.d[i] != Q_NATIVE.d[i] - (i == 0 ? 1 : 0)) {
            return 0;
        }
    }

    return 1;
}

/* ========================================================================
 * Helper: Reduce a scalar modulo q (the order of the curve)
 * ======================================================================== */

void scalar_reduce_mod_q(scalar_native *scalar) {
    int ge = 0;

    /* Check if scalar >= Q by comparing words from Most Significant to Least */
    for (int i = SCALAR_NUM_WORDS - 1; i >= 0; i--) {
        if (scalar->d[i] > Q_NATIVE.d[i]) {
            ge = 1;
            break;
        } else if (scalar->d[i] < Q_NATIVE.d[i]) {
            ge = 0;
            break;
        }
        /* If all words are equal, it's also >= Q */
        if (i == 0) {
            ge = 1;
        }
    }

    if (ge) {
        SCALAR_WORD_TYPE borrow = 0;

        /* Multiple Precision Subtraction (Algorithm 1.2)  */
        for (int i = 0; i < SCALAR_NUM_WORDS; i++) {

            /* Step 6 & 7: (A_i - B_i) mod b and (x_i - k_in) mod b  */
            SCALAR_WORD_TYPE diff = scalar->d[i] - Q_NATIVE.d[i];
            SCALAR_WORD_TYPE res = diff - borrow;

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

int scalar_add(
        private_secret_scalar *result,
        const private_secret_scalar *scalar1,
        const private_secret_scalar *scalar2
) {
    scalar_native native1, native2, native_result;
    SCALAR_WORD_TYPE k_out = 0;

    /* Validate input parameters */
    if (result == NULL || scalar1 == NULL || scalar2 == NULL) {
        return 0;
    }

    /* Parse scalars to native format (validates 0 < scalar < Q) */
    if (!scalar_native_parse(&native1, scalar1)) {
        return 0;
    }
    if (!scalar_native_parse(&native2, scalar2)) {
        return 0;
    }

    /* * Perform Multiple Precision Addition (Algorithm 1.1)
     * This replaces 64-bit casts with logical carry detection.
     */
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        /* Step 6: x_i = (A_i + B_i) mod b */
        SCALAR_WORD_TYPE sum_words = native1.d[i] + native2.d[i];

        /* Step 7: tmp = (x_i + k_in) mod b */
        SCALAR_WORD_TYPE tmp = sum_words + k_out;

        /* * Step 8: k_out = (x_i < A_i) + (tmp < x_i)
         * Carry detection based on the property that a sum with carry
         * is lower than its addends.
         */
        k_out = (sum_words < native1.d[i]) + (tmp < sum_words);

        /* Step 9: Final digit assignment */
        native_result.d[i] = tmp;
    }

    /* * Handle final carry or modular reduction.
     * If k_out (x_n) is 1, the result is >= R > Q.
     */
    if (k_out) {
        SCALAR_WORD_TYPE borrow = 0;
        for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
            SCALAR_WORD_TYPE a_i = native_result.d[i];
            SCALAR_WORD_TYPE b_i = Q_NATIVE.d[i];
            SCALAR_WORD_TYPE diff = a_i - b_i;
            SCALAR_WORD_TYPE res = diff - borrow;
            borrow = (diff > a_i) + (res > diff);
            native_result.d[i] = res;
        }
    } else {
        /* Even without a final carry, result might still be >= Q */
        scalar_reduce_mod_q(&native_result);
    }

    /* Check if result is zero (not allowed for secret scalars) */
    int is_zero = 1;
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        if (native_result.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;
    }

    /* Serialize result back to public format */
    if (!scalar_native_serialize(result, &native_result)) {
        return 0;
    }

    return 1;
}

int scalar_negate(
        private_secret_scalar *result,
        const private_secret_scalar *scalar
) {
    scalar_native native, negated;
    SCALAR_WORD_TYPE borrow = 0;

    /* Validate input parameters */
    if (result == NULL || scalar == NULL) {
        return 0;
    }

    /* Parse scalar to native format (validates 0 < scalar < Q) */
    if (!scalar_native_parse(&native, scalar)) {
        return 0;
    }

    /* * Negate the scalar: negated = Q - native.
     * Implementation based on Multiple Precision Subtraction (Algorithm 1.2).
     */
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE a = Q_NATIVE.d[i];
        SCALAR_WORD_TYPE b = native.d[i];

        /* Compute the result word including the previous borrow */
        SCALAR_WORD_TYPE res = a - b - borrow;

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
     * already filtered by scalar_native_parse.
     */
    int is_zero = 1;
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        if (negated.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;  /* Result cannot be zero for secret scalar */
    }

    /* Serialize negated result to public format */
    if (!scalar_native_serialize(result, &negated)) {
        printf("Error: Failed to serialize negated scalar result\n");
        return 0;
    }

    return 1;
}

void montgomery_mul(
        scalar_native *result,
        const scalar_native *a,
        const scalar_native *b
) {
    /* Accumulatore x con limb extra per il carry finale (SCALAR_NUM_WORDS + 1) */
    SCALAR_WORD_TYPE x[SCALAR_NUM_WORDS + 1] = {0};

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        /* 1. Moltiplicazione-Accumulo della riga: x = x + a[i]*b */
        SCALAR_WORD_TYPE carry1 = 0;
        for (int j = 0; j < SCALAR_NUM_WORDS; j++) {
            x[j] = mul_add_carry(a->d[i], b->d[j], x[j], &carry1);
        }

        /* Gestione del carry che eccede la dimensione dello scalare durante la moltiplicazione */
        SCALAR_WORD_TYPE x_n_prev = x[SCALAR_NUM_WORDS];
        SCALAR_WORD_TYPE x_n_new = x_n_prev + carry1;
        SCALAR_WORD_TYPE carry_n = (x_n_new < x_n_prev) ? 1 : 0;

        /* 2. Calcolo fattore di riduzione Montgomery per questa riga */
        SCALAR_WORD_TYPE t = x[0] * Q_PRIME_0;

        /* 3. Riduzione (passaggio di Montgomery): x = (x + t*Q) / b */
        SCALAR_WORD_TYPE carry2 = 0;
        /* La prima operazione annulla x[0], quindi shiftiamo i risultati di un indice */
        mul_add_carry(t, Q_NATIVE.d[0], x[0], &carry2);

        for (int j = 1; j < SCALAR_NUM_WORDS; j++) {
            x[j - 1] = mul_add_carry(t, Q_NATIVE.d[j], x[j], &carry2);
        }

        /* 4. Consolidamento dei carry finali e completamento dello shift */
        SCALAR_WORD_TYPE sum_low = x_n_new + carry2;
        SCALAR_WORD_TYPE sum_high = (sum_low < x_n_new) ? 1 : 0;
        sum_high += carry_n;

        x[SCALAR_NUM_WORDS - 1] = sum_low;
        x[SCALAR_NUM_WORDS] = sum_high;
    }

    /* 5. Riduzione Finale Condizionale (x = x >= Q ? x - Q : x) */
    SCALAR_WORD_TYPE borrow = 0;
    scalar_native temp_res;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE a_i = x[i];
        SCALAR_WORD_TYPE b_i = Q_NATIVE.d[i];

        SCALAR_WORD_TYPE diff = a_i - b_i - borrow;

        /* Calcolo borrow senza cast */
        if (borrow == 0) {
            borrow = (a_i < b_i) ? 1 : 0;
        } else {
            borrow = (a_i <= b_i) ? 1 : 0;
        }

        temp_res.d[i] = diff;
    }

    SCALAR_WORD_TYPE x_n = x[SCALAR_NUM_WORDS];

    /* Decisione basata sul carry extra (x_n) e sul borrow della sottrazione */
    if (x_n == 1 || borrow == 0) {
        *result = temp_res;
    } else {
        for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
            result->d[i] = x[i];
        }
    }
}

int scalar_mult(
        private_secret_scalar *result,
        const private_secret_scalar *scalar1,
        const private_secret_scalar *scalar2
) {
    scalar_native native1, native2, product;

    /* Parameter validation */
    if (result == NULL || scalar1 == NULL || scalar2 == NULL) {
        return 0;
    }

    /* Parse scalars to native format (validates 0 < scalar < Q) */
    if (!scalar_native_parse(&native1, scalar1)) {
        return 0;
    }
    if (!scalar_native_parse(&native2, scalar2)) {
        return 0;
    }

    /* Convert native scalars into Montgomery form for efficient multiplication */
    scalar_native native1_tilde, native2_tilde;

    montgomery_mul(&native1_tilde, &native1, &R2_NATIVE);
    montgomery_mul(&native2_tilde, &native2, &R2_NATIVE);

    /* Perform Montgomery multiplication: product_tilde = native1_tilde * native2_tilde * R^-1 mod Q */
    scalar_native product_tilde;
    montgomery_mul(&product_tilde, &native1_tilde, &native2_tilde);

    /* Convert product back from Montgomery form to standard representation */
    montgomery_mul(&product, &product_tilde, &ONE_NATIVE);

    /* Check if product is zero (not allowed for secret scalars) */
    int is_zero = 1;
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        if (product.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        return 0;  /* Result cannot be zero for secret scalar */
    }

    /* Serialize product back to public format */
    if (!scalar_native_serialize(result, &product)) {
        return 0;
    }

    return 1;
}