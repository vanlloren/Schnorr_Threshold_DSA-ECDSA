//
// Created by PC on 21/05/2026.
//

#include "utils.h"
#include "rng.h"
#include <string.h>
#include <stdio.h>
#include "scalar_op.h"
#if SECURITY_LEVEL == 128
    #include "secp256r1_curve_params.h"
#elif SECURITY_LEVEL == 256
    #include "secp521r1_curve_params.h"
#endif
#include <sys/random.h>

int nizkp_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const nizkp *nizkp
) {
    uint32_t required_len = 1 + POINT_SIZE + SCALAR_SIZE + SCALAR_SIZE + POINT_SIZE;

    if (*output_len < required_len) {
        return 0;
    }

    unsigned char *cursor = output;
    *cursor = nizkp->generator_index;
    cursor += 1;

    memcpy(cursor, nizkp->u, POINT_SIZE);
    cursor += POINT_SIZE;
    memcpy(cursor, nizkp->c, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(cursor, nizkp->z, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(cursor, nizkp->h, POINT_SIZE);
    cursor += POINT_SIZE;

    *output_len = required_len;

    return 1;
}

int nizkp_parse(
        nizkp *nizkp,
        const unsigned char *input,
        uint32_t input_len
) {
    uint32_t expected_len = 1 + POINT_SIZE + SCALAR_SIZE + SCALAR_SIZE + POINT_SIZE;

    if (input_len != expected_len) {
        return 0;
    }

    const unsigned char *cursor = input;
    nizkp->generator_index = *cursor;
    cursor += 1;
    memcpy(nizkp->u, cursor, POINT_SIZE);
    cursor += POINT_SIZE;
    memcpy(nizkp->c, cursor, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(nizkp->z, cursor, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(nizkp->h, cursor, POINT_SIZE);
    cursor += POINT_SIZE;

    return 1;
}

int recovery_packet_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const keygen_recovery_packet *packet
) {
    uint32_t total_space = *output_len;
    uint32_t bytes_written = 0;
    unsigned char *cursor = output;

    uint32_t fixed_fields_len = 1 + (2 * CIPHERTEXT_SIZE);
    if (total_space < fixed_fields_len) {
        return 0;
    }

    *cursor = packet->generator_index;
    cursor += 1;
    bytes_written += 1;

    memcpy(cursor, packet->encrypted_y_3i, CIPHERTEXT_SIZE);
    cursor += CIPHERTEXT_SIZE;
    bytes_written += CIPHERTEXT_SIZE;

    memcpy(cursor, packet->encrypted_y_i3, CIPHERTEXT_SIZE);
    cursor += CIPHERTEXT_SIZE;
    bytes_written += CIPHERTEXT_SIZE;

    uint32_t remaining_space = total_space - bytes_written;
    uint32_t nizkp_1_len = remaining_space;


    if (!nizkp_serialize(cursor, &nizkp_1_len, &(packet->nizkp_y_3i))) {
        return 0;
    }
    cursor += nizkp_1_len;
    bytes_written += nizkp_1_len;

    remaining_space = total_space - bytes_written;
    uint32_t nizkp_2_len = remaining_space;


    if (!nizkp_serialize(cursor, &nizkp_2_len, &(packet->nizkp_y_i3))) {
        return 0;
    }
    bytes_written += nizkp_2_len;
    *output_len = bytes_written;

    return 1;
}

int recovery_packet_parse(
        keygen_recovery_packet *packet,
        const unsigned char *input,
        uint32_t input_len
) {
    uint32_t expected_nizkp_len = 1 + POINT_SIZE + SCALAR_SIZE + SCALAR_SIZE + POINT_SIZE;
    uint32_t total_expected_len = 1 + (2 * CIPHERTEXT_SIZE) + (2 * expected_nizkp_len);

    if (input_len != total_expected_len) {
        return 0;
    }

    const unsigned char *cursor = input;
    packet->generator_index = *cursor;
    cursor += 1;

    memcpy(packet->encrypted_y_3i, cursor, CIPHERTEXT_SIZE);
    cursor += CIPHERTEXT_SIZE;

    memcpy(packet->encrypted_y_i3, cursor, CIPHERTEXT_SIZE);
    cursor += CIPHERTEXT_SIZE;

    if (!nizkp_parse(&(packet->nizkp_y_3i), cursor, expected_nizkp_len)) {
        return 0;
    }
    cursor += expected_nizkp_len;

    if (!nizkp_parse(&(packet->nizkp_y_i3), cursor, expected_nizkp_len)) {
        return 0;
    }

    return 1;
}

int keygen_shamir_secret_share_serialize(
        unsigned char *output,
        const keygen_shamir_secret_share *share
) {
    unsigned char *cursor = output;
    *cursor = share->generator_index;
    cursor += 1;
    *cursor = share->receiver_index;
    cursor += 1;
    memcpy(cursor, share->value, SCALAR_SIZE);
    return 1;
}

int keygen_shamir_secret_share_parse(
        keygen_shamir_secret_share *share,
        const unsigned char *input
) {
    const unsigned char *cursor = input;
    share->generator_index = *cursor;
    cursor += 1;
    share->receiver_index = *cursor;
    cursor += 1;
    memcpy(share->value, cursor, SCALAR_SIZE);
    return 1;
}

int schnorr_pubkey_parse(
        schnorr_pubkey *pubkey,
        const unsigned char *input,
        uint8_t inputlen
) {
    if (inputlen != POINT_SIZE) {
        return 0;
    }
    if (input[0] != 0x04) {
        return 0;
    }
    memcpy(pubkey->point.value, input, POINT_SIZE);
    pubkey->point.generator_index = 0;

    return 1;
}

int schnorr_pubkey_serialize(
        unsigned char *output,
        uint8_t *outputlen,
        const schnorr_pubkey *pubkey
) {
    if (*outputlen < POINT_SIZE) {
        return 0;
    }
    memcpy(output, pubkey->point.value, POINT_SIZE);
    *outputlen = POINT_SIZE;
    return 1;
}

int commit_point(
        commitment_packet *commitment_packet,
        const point_extended *point,
        const uint16_t dsc,
        CSPRNG_STATE_T *csprng_state
) {
    private_secret_scalar nonce;
    nonce.generator_index = point->generator_index;
    int valid = 0;

    while (!valid) {
        csprng_randombytes(nonce.value, SCALAR_SIZE, csprng_state);
        if (scalar_verify(&nonce)) {
            valid = 1;
        }
    }

    unsigned char m[SCALAR_SIZE *2 + 16];
    unsigned char *m_cursor = m;

    uint64_t x_len_le = SCALAR_SIZE;
    memcpy(m_cursor, &x_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, &(point->value[1]), SCALAR_SIZE);
    m_cursor += 32;

    uint64_t y_len_le = SCALAR_SIZE;
    memcpy(m_cursor, &y_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, &(point->value[1+SCALAR_SIZE]), SCALAR_SIZE);

    unsigned char hash_digest[32];
    uint8_t counter = 1;

    hash(hash_digest, nonce.value, m, SCALAR_SIZE *2 + 16, dsc, counter);

    commitment_packet->generator_index = point->generator_index;
    memcpy(commitment_packet->commitment.data, hash_digest, 32);
    memcpy(commitment_packet->decommitment.nonce, nonce.value, SCALAR_SIZE);

    if (POINT_SIZE > MAX_COMMITMENT_SIZE) {
        return 0;
    }
    memcpy(commitment_packet->decommitment.value, point->value, POINT_SIZE);
    commitment_packet->decommitment.value_len = POINT_SIZE;

    return 1;
}

int commit_scalar(
        commitment_packet *commitment_packet,
        const private_secret_scalar *scalar,
        const uint16_t dsc,
        CSPRNG_STATE_T *csprng_state
) {
    private_secret_scalar nonce;
    nonce.generator_index = scalar->generator_index;
    int valid = 0;

    while (!valid) {
        csprng_randombytes(nonce.value, 32, csprng_state);
        if (scalar_verify(&nonce)) {
            valid = 1;
        }
    }

    unsigned char m[SCALAR_SIZE + 8];
    unsigned char *m_cursor = m;

    uint64_t value_len_le = SCALAR_SIZE;
    memcpy(m_cursor, &value_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, scalar->value, SCALAR_SIZE);

    unsigned char hash_digest[32];
    uint8_t counter = 1;
    hash(hash_digest, nonce.value, m, SCALAR_SIZE+8, dsc, counter);

    commitment_packet->generator_index = scalar->generator_index;
    memcpy(commitment_packet->commitment.data, hash_digest, 32);
    memcpy(commitment_packet->decommitment.nonce, nonce.value, SCALAR_SIZE);

    if (SCALAR_SIZE > MAX_COMMITMENT_SIZE) {
        return 0; //
    }

    memcpy(commitment_packet->decommitment.value, scalar->value, SCALAR_SIZE);
    commitment_packet->decommitment.value_len = SCALAR_SIZE;

    return 1;
}

int rejection_sampling_q(const unsigned char *scalar) {
    if (memcmp(scalar, zero, SCALAR_SIZE) == 0) {
        return 0;
    }
    if (memcmp(scalar, one, SCALAR_SIZE) == 0) {
        return 0;
    }
    if (memcmp(scalar, q_minus_one, SCALAR_SIZE) == 0) {
        return 0;
    }
    if (memcmp(scalar, q, SCALAR_SIZE) == 0) {
        return 0;
    }

    for (int i = 0; i < SCALAR_SIZE; i++) {
        if (scalar[i] > q[i]) {
            return 0;
        }
        if (scalar[i] < q[i]) {
            break;
        }
    }

    return 1;
}