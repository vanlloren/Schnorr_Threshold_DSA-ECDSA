//
// Created by PC on 05/05/2026.
//

#include "EC_arithmetics.h"
#include "scalar_op.h"
#if SECURITY_LEVEL == 128
    #include "secp256r1_G_precomputed_table.h"
#elif SECURITY_LEVEL == 256
    #include "secp521r1_G_precomputed_table.h"
#endif
#include <string.h>
#include <stdint.h>
#include <stdio.h>

const point_coord_native P_NATIVE = { { P_WORDS } };
const point_coord_native P_PRIME_NATIVE = { { P_PRIME_0 } };
const point_coord_native P_R2_NATIVE = { { P_R2_WORDS } };
const point_coord_native P_ONE_NATIVE = { { ONE_WORDS } };
const point_coord_native P_MINUS_2_NATIVE = { { P_MINUS_2_WORDS } };
const point_coord_native P_B_MONTGOMERY = { { P_B_MONTGOMERY_WORDS } };
const point_coord_native P_R_MONTGOMERY = { { P_R_MONTGOMERY_WORDS } };
const point_coord_native P_A_MONTGOMERY = { { P_A_MONTGOMERY_WORDS } };
const point_coord_native P_A = { { P_A_WORDS } };

static inline void print_hex_256(const char* label, const uint32_t* d) {
    printf("%s: ", label);
    // Stampiamo dalla word 7 (MSB) alla word 0 (LSB)
    for (int i = 7; i >= 0; i--) {
        printf("%08X", d[i]);
    }
    printf("\n");
}

/* ========================================================================
 * Utility functions for endianness conversion
 * ======================================================================== */

/** Convert a point coordinate (SCALAR_SIZE bytes) from bytes in big-endian order to native format.
 *
 * Params:
 * In:      in: pointer to the byte array containing the coordinate in big-endian order
 * Out:     out: pointer to the point coordinate in native format to store the result
 *
 */
static inline void bytes_to_point_coord_native(point_coord_native *out, const unsigned char *in) {
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;
    const int scalar_size = SCALAR_NUM_WORDS * bytes_per_word;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        out->d[i] = 0;
        for (int j = 0; j < bytes_per_word; j++) {
            /*
            * Index explanation:
            * (scalar_size - 1) is the last byte of the array (LSB in Big-Endian).
            * (i * bytes_per_word) moves us to the correct word.
            * j moves us within the word.
            */
            int byte_idx = (scalar_size - 1) - (i * bytes_per_word) - j;
            out->d[i] |= ((SCALAR_WORD_TYPE)in[byte_idx] << (8 * j));
        }
    }
}

/** Convert a point coordinate from native format to bytes in big-endian order.
 *
 * Params:
 * In:      in: pointer to the point coordinate in native format
 * Out:     out: pointer to the byte array (SCALAR_SIZE bytes) to store the result
 *
 */
static inline void point_coord_native_to_bytes(unsigned char *out, const point_coord_native *in) {
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;
    const int scalar_size = SCALAR_NUM_WORDS * bytes_per_word;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        for (int j = 0; j < bytes_per_word; j++) {
            /*
            * Index calculation:
            * We start from the end of the array (scalar_size - 1) since it's Big-Endian.
            * Subtract the space occupied by previous words (i * bytes_per_word).
            * Subtract the offset of the current byte within the word (j).
            */
            int byte_idx = (scalar_size - 1) - (i * bytes_per_word) - j;

            /*
            * Extract the j-th byte from the i-th word.
            * Shift right by 0, 8, 16, 24... bits and mask to isolate the byte.
             */
            out[byte_idx] = (unsigned char)((in->d[i] >> (8 * j)) & 0xFF);
        }
    }
}

/* ========================================================================
 * Utility functions
 * ======================================================================== */
/** Check if a point coordinate in native format is zero.
 *
 * Returns: 1 if the coordinate is zero, 0 otherwise.
 * In:      d: pointer to the point coordinate in native format
 */
static inline int sec_is_zero(const SCALAR_WORD_TYPE *d) {
    SCALAR_WORD_TYPE accumulator = 0;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        accumulator |= d[i];
    }

    return (accumulator == 0);
}

/** Check if two point coordinates in native format are equal.
 *
 * Returns: 1 if the coordinates are equal, 0 otherwise.
 * In:      a: pointer to the first point coordinate in native format
 * b: pointer to the second point coordinate in native format
 */
static inline int sec_native_equal(const SCALAR_WORD_TYPE *a, const SCALAR_WORD_TYPE *b) {
    SCALAR_WORD_TYPE accumulator = 0;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        accumulator |= (a[i] ^ b[i]);
    }

    return (accumulator == 0);
}

void field_p_montgomery_mul(
        point_coord_native *result,
        const point_coord_native *a,
        const point_coord_native *b
) {
    /* Accumulatore x con limb extra per il carry finale (8 + 1 = 9 words) */
    SCALAR_WORD_TYPE x[SCALAR_NUM_WORDS + 1] = {0};

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        /* 1. Moltiplicazione-Accumulo della riga: x = x + a[i]*b */
        SCALAR_WORD_TYPE carry1 = 0;
        for (int j = 0; j < SCALAR_NUM_WORDS; j++) {
            x[j] = mul_add_carry(a->d[i], b->d[j], x[j], &carry1);
        }

        /* Gestione del carry che eccede i 256 bit durante la moltiplicazione */
        SCALAR_WORD_TYPE x_n_prev = x[SCALAR_NUM_WORDS];
        SCALAR_WORD_TYPE x_n_new = x_n_prev + carry1;
        SCALAR_WORD_TYPE carry_n = (x_n_new < x_n_prev) ? 1 : 0;

        /* 2. Calcolo fattore di riduzione Montgomery per questa riga */
        SCALAR_WORD_TYPE t = x[0] * P_PRIME_0;

        /* 3. Riduzione (passaggio di Montgomery): x = (x + t*Q) / b */
        SCALAR_WORD_TYPE carry2 = 0;
        /* La prima operazione annulla x[0], quindi shiftiamo i risultati di un indice */
        mul_add_carry(t, P_NATIVE.d[0], x[0], &carry2);

        for (int j = 1; j < SCALAR_NUM_WORDS; j++) {
            x[j - 1] = mul_add_carry(t, P_NATIVE.d[j], x[j], &carry2);
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
    point_coord_native temp_res;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE a_i = x[i];
        SCALAR_WORD_TYPE b_i = P_NATIVE.d[i];

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

/** Add two field elements in native format and reduce modulo P.
 *
 * Params:
 * In:      a: pointer to the first field element in native format
 * b: pointer to the second field element in native format
 * Out:     out: pointer to the field element in native format to store the result
 *
 * This function performs a multi-precision addition of a and b, then checks if the result is greater than or equal to P.
 * If it is, it subtracts P to ensure the result is reduced modulo P. The entire operation is done in constant time to prevent side-channel attacks.
 */
static inline void field_p_add(
        point_coord_native *out,
        const point_coord_native *a,
        const point_coord_native *b
) {
    SCALAR_WORD_TYPE k_out = 0;
    point_coord_native sum_result;

    // 1. Somma: sum_result = a + b
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE a_i = a->d[i];
        SCALAR_WORD_TYPE b_i = b->d[i];

        SCALAR_WORD_TYPE sum_words = a_i + b_i;
        SCALAR_WORD_TYPE tmp = sum_words + k_out;

        // Determina il carry: 1 se c'è stato overflow
        k_out = (sum_words < a_i) | (tmp < sum_words);
        sum_result.d[i] = tmp;
    }

    SCALAR_WORD_TYPE borrow = 0;
    point_coord_native diff_result;

    // 2. Sottrazione: diff_result = sum_result - P
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE s_i = sum_result.d[i];
        SCALAR_WORD_TYPE p_i = P_NATIVE.d[i];

        SCALAR_WORD_TYPE diff = s_i - p_i;
        SCALAR_WORD_TYPE res = diff - borrow;

        // Correzione propagazione borrow (senza cast 64-bit)
        // Il prestito si genera se s_i < p_i o se il borrow precedente ha causato underflow su zero
        borrow = (s_i < p_i) | ((s_i == p_i) & borrow);

        diff_result.d[i] = res;
    }

    /* * LOGICA DELLA MASCHERA:
     * Dobbiamo scegliere diff_result (riduzione) se:
     * 1. La somma ha prodotto un carry (k_out == 1), quindi il numero è >= 2^256 > P.
     * 2. La sottrazione NON ha prodotto un borrow (borrow == 0), quindi sum_result >= P.
     * In tutti gli altri casi, usiamo sum_result.
     */
    SCALAR_WORD_TYPE mask = (SCALAR_WORD_TYPE)-(int32_t)(k_out | (borrow ^ 1));

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        out->d[i] = (diff_result.d[i] & mask) | (sum_result.d[i] & ~mask);
    }
}

/** Subtract two field elements in native format and reduce modulo P.
 *
 * Params:
 * In:      a: pointer to the first field element in native format
 * b: pointer to the second field element in native format
 * Out:     out: pointer to the field element in native format to store the result
 *
 * This function performs a multi-precision subtraction of b from a. If the result is negative, it adds P to ensure the result is reduced modulo P. The entire operation is done in constant time to prevent side-channel attacks.
 */
static inline void field_p_sub(
        point_coord_native *out,
        const point_coord_native *a,
        const point_coord_native *b
) {
    SCALAR_WORD_TYPE k_out = 0;
    point_coord_native sub_result;

    /* 1. Multiple Precision Subtraction (Algoritmo 1.2) */
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE x_i = a->d[i] - b->d[i];
        SCALAR_WORD_TYPE tmp = x_i - k_out;

        k_out = (x_i > a->d[i]) + (tmp > x_i);
        sub_result.d[i] = tmp;
    }

    SCALAR_WORD_TYPE carry = 0;
    point_coord_native add_p_result;

    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        SCALAR_WORD_TYPE s_i = sub_result.d[i];
        SCALAR_WORD_TYPE p_i = P_NATIVE.d[i];
        SCALAR_WORD_TYPE sum_words = s_i + p_i;
        SCALAR_WORD_TYPE res = sum_words + carry;
        carry = (sum_words < s_i) + (res < sum_words);
        add_p_result.d[i] = res;
    }

    SCALAR_WORD_TYPE mask = (SCALAR_WORD_TYPE)-(int32_t)k_out;
    for (int i = 0; i < SCALAR_NUM_WORDS; i++) {
        out->d[i] = (add_p_result.d[i] & mask) | (sub_result.d[i] & ~mask);
    }
}

int point_ge_parse(
        point_ge *point,
        const point_extended *input
) {
    if (!point || !input) return 0;

    point->generator_index = input->generator_index;
    point_coord_native raw_x, raw_y;

    bytes_to_point_coord_native(&raw_x, &input->value[1]);
    bytes_to_point_coord_native(&raw_y, &input->value[SCALAR_SIZE + 1]);

    field_p_montgomery_mul(&point->x, &raw_x, &P_R2_NATIVE);
    field_p_montgomery_mul(&point->y, &raw_y, &P_R2_NATIVE);

    if (sec_is_zero(raw_x.d) && sec_is_zero(raw_y.d)) {
        point->infinity = 1;
    } else {
        point->infinity = 0;
    }

    return 1;
}

int point_ge_serialize(
        point_extended *output,
        const point_ge *point
) {
    if (output == NULL || point == NULL) {
        return 0;
    }

    output->generator_index = point->generator_index;


    // set infinity
    if (point->infinity) {
        memset(&output->value[1], 0, SCALAR_SIZE);
        memset(&output->value[SCALAR_SIZE+1], 0, SCALAR_SIZE);
        return 1;
    }

    point_coord_native x_std, y_std;

    field_p_montgomery_mul(&x_std, &point->x, &P_ONE_NATIVE);
    field_p_montgomery_mul(&y_std, &point->y, &P_ONE_NATIVE);

    //set byte 0 to 0x04 to indicate uncompressed format
    output->value[0] = 0x04;
    point_coord_native_to_bytes(&output->value[1], &x_std);
    point_coord_native_to_bytes(&output->value[SCALAR_SIZE+1], &y_std);


    return 1;
}

int point_ge_to_gej(
        point_gej *output,
        const point_ge *point
) {
    if (!output || !point) return 0;

    output->generator_index = point->generator_index;
    output->infinity = point->infinity;

    if (point->infinity) {
        memset(&output->X, 0, sizeof(output->X));
        memset(&output->Y, 0, sizeof(output->Y));
        memset(&output->Z, 0, sizeof(output->Z));
    } else {
        output->X = point->x;
        output->Y = point->y;
        output->Z = P_R_MONTGOMERY;
    }

    return 1;
}

int point_gej_to_ge(
        point_ge *point,
        const point_gej *input
) {
    if (!point || !input) return 0;

    point->generator_index = input->generator_index;
    point->infinity = input->infinity;

    if (input->infinity || sec_is_zero(input->Z.d)) {
        point->infinity = 1;
        memset(&point->x, 0, sizeof(point->x));
        memset(&point->y, 0, sizeof(point->y));
        return 1;
    }

    point_coord_native z1, z2, z3;
    field_p_inverse(&z1, &input->Z);
    field_p_montgomery_mul(&z2, &z1, &z1);
    field_p_montgomery_mul(&point->x, &input->X, &z2);
    field_p_montgomery_mul(&z3, &z2, &z1);
    field_p_montgomery_mul(&point->y, &input->Y, &z3);

    return 1;
}

int point_gej_is_infinity(const point_gej *point) {
    return (point->infinity || sec_is_zero(point->Z.d));
}

int point_gej_set_infinity(point_gej *point) {
    point->infinity = 1;

    memset(&point->X, 0, sizeof(point->X));
    memset(&point->Y, 0, sizeof(point->Y));
    memset(&point->Z, 0, sizeof(point->Z));
    return 1;
}

int point_gej_is_valid(const point_gej *point) {
    if (point_gej_is_infinity(point)) return 1;

    point_coord_native y2, x3, z2, z4, z6, tmp, rhs, parsum;

    /* Y^2 */
    field_p_montgomery_mul(&y2, &point->Y, &point->Y);

    /* X^3 + aXz^4 + bZ^6 */
    field_p_montgomery_mul(&z2, &point->Z, &point->Z);   // Z^2
    field_p_montgomery_mul(&z4, &z2, &z2);             // Z^4
    field_p_montgomery_mul(&z6, &z4, &z2);             // Z^6

    // X^3
    field_p_montgomery_mul(&tmp, &point->X, &point->X);
    field_p_montgomery_mul(&x3, &tmp, &point->X);

    // aXZ^4
    point_coord_native tmp2, tmp3, tmp4;
    field_p_montgomery_mul(&tmp4, &point->X, &z4);

    //field_p_montgomery_mul(&tmp2, &tmp4, &P_A_MONTGOMERY);
    //field_p_add(&parsum, &x3, &tmp2);

    // X^3 - 3XZ^4
    field_p_sub(&parsum, &x3, &tmp4);
    field_p_sub(&parsum, &parsum, &tmp4);
    field_p_sub(&parsum, &parsum, &tmp4);

    // bZ^6
    field_p_montgomery_mul(&tmp3, &z6, &P_B_MONTGOMERY);

    field_p_add(&rhs, &parsum, &tmp3);

    // Ritorna 1 se y2 == rhs
    return sec_native_equal(y2.d, rhs.d);
}

int point_gej_equal(
        const point_gej *point1,
        const point_gej *point2
) {
    int inf1 = point_gej_is_infinity(point1);
    int inf2 = point_gej_is_infinity(point2);

    if (inf1 || inf2) {
        return (inf1 && inf2);
    }

    point_coord_native z1_2, z2_2, u1, u2, s1, s2;

    field_p_montgomery_mul(&z1_2, &point1->Z, &point1->Z);
    field_p_montgomery_mul(&z2_2, &point2->Z, &point2->Z);
    field_p_montgomery_mul(&u1, &point1->X, &z2_2);
    field_p_montgomery_mul(&u2, &point2->X, &z1_2);

    if (!sec_native_equal(u1.d, u2.d)) {
        return 0;
    }

    field_p_montgomery_mul(&s1, &point1->Y, &z2_2);
    field_p_montgomery_mul(&s1, &s1, &point2->Z);
    field_p_montgomery_mul(&s2, &point2->Y, &z1_2);
    field_p_montgomery_mul(&s2, &s2, &point1->Z);

    return sec_native_equal(s1.d, s2.d);
}

int point_gej_negate(
        point_gej *result,
        const point_gej *point
) {
    if (result == NULL || point == NULL) {
        return 0;
    }

    result->X = point->X;
    result->Z = point->Z;
    result->infinity = point->infinity;
    result->generator_index = point->generator_index;

    if (point->infinity) {
        memset(&result->Y, 0, sizeof(result->Y));
        return 1;
    }

    point_coord_native zero = {0};
    field_p_sub(&result->Y, &zero, &point->Y);

    return 1;
}

int point_gej_add(
        point_gej *result,
        const point_gej *point1,
        const point_gej *point2
) {
    if (point1->infinity) {
        *result = *point2;
        return 1;
    }
    if (point2->infinity) {
        *result = *point1;
        return 1;
    }

    if (point_gej_equal(point1, point2)) {
        return point_gej_double(result, point1);
    }

    point_coord_native z1z1, z2z2, u1, u2, s1, s2, h, r, h2, h3, u1h2;

    field_p_montgomery_mul(&z1z1, &point1->Z, &point1->Z);
    field_p_montgomery_mul(&z2z2, &point2->Z, &point2->Z);

    /* U1 = X1 * Z2^2, U2 = X2 * Z1^2 */
    field_p_montgomery_mul(&u1, &point1->X, &z2z2);
    field_p_montgomery_mul(&u2, &point2->X, &z1z1);

    /* S1 = Y1 * Z2^3, S2 = Y2 * Z1^3 */
    field_p_montgomery_mul(&s1, &point1->Y, &z2z2);
    field_p_montgomery_mul(&s1, &s1, &point2->Z);
    field_p_montgomery_mul(&s2, &point2->Y, &z1z1);
    field_p_montgomery_mul(&s2, &s2, &point1->Z);

    /* H = U2 - U1, R = S2 - S1 */
    field_p_sub(&h, &u2, &u1);
    field_p_sub(&r, &s2, &s1);

    /* H^2 e H^3 */
    field_p_montgomery_mul(&h2, &h, &h);
    field_p_montgomery_mul(&h3, &h2, &h);

    /* U1 * H^2 */
    field_p_montgomery_mul(&u1h2, &u1, &h2);

    /* X3 = R^2 - H^3 - 2*(U1*H^2) */
    field_p_montgomery_mul(&result->X, &r, &r);
    field_p_sub(&result->X, &result->X, &h3);
    field_p_sub(&result->X, &result->X, &u1h2);
    field_p_sub(&result->X, &result->X, &u1h2);

    /* Y3 = R * (U1*H^2 - X3) - S1*H^3 */
    point_coord_native tmp;
    field_p_sub(&tmp, &u1h2, &result->X);
    field_p_montgomery_mul(&result->Y, &r, &tmp);
    field_p_montgomery_mul(&tmp, &s1, &h3);
    field_p_sub(&result->Y, &result->Y, &tmp);

    /* Z3 = H * Z1 * Z2 */
    field_p_montgomery_mul(&result->Z, &point1->Z, &point2->Z);
    field_p_montgomery_mul(&result->Z, &result->Z, &h);

    if (sec_is_zero(result->Z.d)) {
        result->infinity = 1;
    } else {
        result->infinity = 0;
    }

    return 1;
}

int point_gej_double(
        point_gej *result,
        const point_gej *point
) {
    if (!result || !point) return 0;

    if (point->infinity || sec_is_zero(point->Y.d)) {
        result->infinity = 1;
        result->generator_index = point->generator_index;
        return 1;
    }

    // Creiamo una struttura temporanea nello stack per proteggere l'in-place
    point_gej local_res;
    local_res.generator_index = point->generator_index;

    point_coord_native m, s, t;
    point_coord_native z2_sq, tmp1, tmp2, y2;

    /* m = 3*(X - Z^2)*(X + Z^2) */
    field_p_montgomery_mul(&z2_sq, &point->Z, &point->Z);
    field_p_sub(&tmp1, &point->X, &z2_sq);
    field_p_add(&tmp2, &point->X, &z2_sq);
    field_p_montgomery_mul(&m, &tmp1, &tmp2);

    /* m = 3 * m */
    tmp1 = m;
    field_p_add(&m, &tmp1, &tmp1);
    field_p_add(&m, &m, &tmp1);

    /* s = 4 * X * Y^2 */
    field_p_montgomery_mul(&y2, &point->Y, &point->Y);
    field_p_montgomery_mul(&s, &point->X, &y2);
    tmp1 = s;
    field_p_add(&s, &tmp1, &tmp1);
    field_p_add(&s, &s, &s);

    /* t = 8 * Y^4 */
    field_p_montgomery_mul(&t, &y2, &y2);
    tmp1 = t;
    field_p_add(&t, &tmp1, &tmp1);
    field_p_add(&t, &t, &t);
    field_p_add(&t, &t, &t);

    /* X3 = m^2 - 2*s */
    field_p_montgomery_mul(&local_res.X, &m, &m);
    field_p_sub(&local_res.X, &local_res.X, &s);
    field_p_sub(&local_res.X, &local_res.X, &s);

    /* Y3 = m * (s - X3) - t */
    field_p_sub(&tmp1, &s, &local_res.X);
    field_p_montgomery_mul(&local_res.Y, &m, &tmp1);
    field_p_sub(&local_res.Y, &local_res.Y, &t);

    /* Z3 = 2 * Y * Z */
    field_p_montgomery_mul(&local_res.Z, &point->Y, &point->Z);
    tmp1 = local_res.Z;
    field_p_add(&local_res.Z, &tmp1, &tmp1);

    if (sec_is_zero(local_res.Z.d)) {
        local_res.infinity = 1;
    } else {
        local_res.infinity = 0;
    }

    // Scrittura finale sull'output (ora l'operazione in-place è safe!)
    *result = local_res;
    return 1;
}

int point_gej_add_ge(
        point_gej *result,
        const point_gej *point_jac,
        const point_ge *point_aff
) {
    result->generator_index = point_jac->generator_index;

    if (point_jac->infinity) {
        result->X = point_aff->x;
        result->Y = point_aff->y;
        result->Z = P_R_MONTGOMERY;
        result->infinity = point_aff->infinity;
        return 1;
    }
    if (point_aff->infinity) {
        *result = *point_jac;
        return 1;
    }

    point_coord_native z1z1, u2, s2, h, r, h2, h3, u1h2, tmp;

    /* Z1^2 */
    field_p_montgomery_mul(&z1z1, &point_jac->Z, &point_jac->Z);

    /* U2 = X_aff * Z1^2 */
    field_p_montgomery_mul(&u2, &point_aff->x, &z1z1);

    /* S2 = Y_aff * Z1^3 = Y_aff * Z1^2 * Z1 */
    field_p_montgomery_mul(&s2, &point_aff->y, &z1z1);
    field_p_montgomery_mul(&s2, &s2, &point_jac->Z);

    if (sec_native_equal(point_jac->X.d, u2.d)) {
        if (sec_native_equal(point_jac->Y.d, s2.d)) {
            return point_gej_double(result, point_jac);
        } else {
            result->infinity = 1;
            return 1;
        }
    }

    /* H = U2 - X1, R = S2 - Y1 */
    field_p_sub(&h, &u2, &point_jac->X);
    field_p_sub(&r, &s2, &point_jac->Y);

    /* H^2 e H^3 */
    field_p_montgomery_mul(&h2, &h, &h);
    field_p_montgomery_mul(&h3, &h2, &h);

    /* U1*H^2 (qui U1 è X1) */
    field_p_montgomery_mul(&u1h2, &point_jac->X, &h2);

    /* X3 = R^2 - H^3 - 2*U1H2 */
    field_p_montgomery_mul(&result->X, &r, &r);
    field_p_sub(&result->X, &result->X, &h3);
    field_p_sub(&result->X, &result->X, &u1h2);
    field_p_sub(&result->X, &result->X, &u1h2);

    /* Y3 = R * (U1H2 - X3) - Y1*H^3 */
    field_p_sub(&tmp, &u1h2, &result->X);
    field_p_montgomery_mul(&result->Y, &r, &tmp);
    field_p_montgomery_mul(&tmp, &point_jac->Y, &h3);
    field_p_sub(&result->Y, &result->Y, &tmp);

    /* Z3 = H * Z1 */
    field_p_montgomery_mul(&result->Z, &point_jac->Z, &h);

    result->infinity = 0;
    return 1;
}

int point_gej_scalar_mult_base(
        point_gej *result,
        const private_secret_scalar *scalar
) {
    if (!result || !scalar) return 0;

    // 1. Inizializzazione pulita all'infinito
    result->infinity = 1;
    result->generator_index = scalar->generator_index;
    memset(&result->X, 0, sizeof(result->X));
    memset(&result->Y, 0, sizeof(result->Y));
    memset(&result->Z, 0, sizeof(result->Z));

    int first_window = 1;

    // 2. Parametrizzazione dinamica basata sulla Window Size e sulla dimensione dello scalare
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;
    const int scalar_bytes = SCALAR_NUM_WORDS * bytes_per_word;

    // Calcoliamo quante finestre (finestre di bit) ci sono in 1 byte (8 bit)
    // w=8 -> 1 | w=4 -> 2 | w=2 -> 4
    const int windows_per_byte = 8 / WINDOW_SIZE;

    // Creiamo la maschera per isolare i bit della finestra
    // w=8 -> 0xFF | w=4 -> 0x0F | w=2 -> 0x03
    const uint8_t window_mask = (1 << WINDOW_SIZE) - 1;

    // Scorriamo i byte dello scalare (da MSB a LSB) - GENERALIZZATO
    for (int i = 0; i < scalar_bytes; i++) {
        uint8_t byte = scalar->value[i];

        // Scorriamo le finestre all'interno del singolo byte da sinistra a destra
        for (int j = 0; j < windows_per_byte; j++) {

            // Calcoliamo lo shift necessario per estrarre la finestra corrente.
            // Esempio con w=4:
            // j=0 -> shift = 8 - 4 - 0 = 4 (Estrae il nibble alto)
            // j=1 -> shift = 8 - 4 - 4 = 0 (Estrae il nibble basso)
            int shift = 8 - WINDOW_SIZE - (j * WINDOW_SIZE);

            uint8_t window_val = (byte >> shift) & window_mask;

            // Se l'accumulatore ha già dati, dobbiamo raddoppiarlo tante volte quant'è l'ampiezza della finestra
            if (!first_window) {
                // Eseguiamo un numero di raddoppi consecutivi pari a WINDOW_SIZE
                for (int d = 0; d < WINDOW_SIZE; d++) {
                    point_gej tmpl_double;
                    point_gej_double(&tmpl_double, result);
                    *result = tmpl_double; // Copia in sicurezza (protezione anti in-place)
                }
            }

            // Se la finestra contiene un valore numerico > 0, aggiungiamo il punto precalcolato
            if (window_val > 0) {
                // Recuperiamo il punto corrispondente (l'indice è window_val - 1)
                const point_ge *point_to_add = &PRECOMPUTED_G[window_val - 1];

                if (first_window) {
                    // Primo punto in assoluto: copia diretta per inizializzare l'accumulatore
                    result->X = point_to_add->x;
                    result->Y = point_to_add->y;
                    result->Z = P_R_MONTGOMERY;
                    result->infinity = point_to_add->infinity;
                    first_window = 0;
                } else {
                    // Somme successive: addizione mista Jacobiano + Affine
                    point_gej tmpl_add;
                    point_gej_add_ge(&tmpl_add, result, point_to_add);
                    *result = tmpl_add; // Copia strutturale in sicurezza
                }
            }
        }
    }

    return 1;
}

int point_gej_scalar_mult(
        point_gej *result,
        const point_gej *point,
        const private_secret_scalar *scalar
) {
    if (!result || !point || !scalar) return 0;

    // 1. Inizializzazione pulita all'infinito
    result->infinity = 1;
    result->generator_index = scalar->generator_index; // Se applicabile
    memset(&result->X, 0, sizeof(result->X));
    memset(&result->Y, 0, sizeof(result->Y));
    memset(&result->Z, 0, sizeof(result->Z));

    int first_bit = 1;

    // Calcolo dinamico della dimensione dello scalare in byte
    const int bytes_per_word = SCALAR_WORD_SIZE / 8;
    const int scalar_bytes = SCALAR_NUM_WORDS * bytes_per_word;

    // Scorriamo i byte dello scalare (da MSB a LSB) - GENERALIZZATO
    for (int i = 0; i < scalar_bytes; i++) {
        uint8_t byte = scalar->value[i];

        // Scorriamo i singoli bit del byte da sinistra a destra (dal bit 7 al bit 0)
        for (int b = 7; b >= 0; b--) {
            // Estraiamo il singolo bit corrente (0 oppure 1)
            uint8_t bit_val = (byte >> b) & 0x01;

            // Se abbiamo già iniziato ad accumulare il punto, dobbiamo SEMPRE raddoppiare.
            // Usiamo una variabile temporanea per proteggerci dai bug in-place di gej_double.
            if (!first_bit) {
                point_gej tmpl_double;
                point_gej_double(&tmpl_double, result);
                *result = tmpl_double; // Copia strutturale del punto raddoppiato in sicurezza
            }

            // Se il bit corrente è 1, dobbiamo aggiungere il punto base "point"
            if (bit_val == 1) {
                if (first_bit) {
                    // Primo bit a 1 incontrato: copiamo direttamente il punto di input
                    // (sia esso in formato affine o già Jacobiano pieno)
                    result->X = point->X;
                    result->Y = point->Y;
                    result->Z = point->Z;
                    result->infinity = point->infinity;
                    first_bit = 0;
                } else {
                    // Bit a 1 successivi: addizione Jacobiano + Jacobiano standard.
                    // Anche qui usiamo un buffer per evitare conflitti in-place.
                    point_gej tmpl_add;

                    // NOTA: Qui si usa l'addizione Jacobiana completa (gej_add o equivalente),
                    // poiché l'input 'point' è un point_gej e non un _ge affine.
                    point_gej_add(&tmpl_add, result, point);
                    *result = tmpl_add;
                }
            }
        }
    }

    return 1;
}