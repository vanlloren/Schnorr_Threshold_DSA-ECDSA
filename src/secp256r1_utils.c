//
// Created by PC on 21/05/2026.
//

#include "secp256r1_utils.h"
#include "rng.h"
#include <string.h>
#include <stdio.h>
#include "secp256r1_scalar_op.h"
#include "secp256r1_curve_params.h"
#include <sys/random.h>

int secp256r1_nizkp_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_nizkp *nizkp
) {
    uint32_t required_len = 1 + 65 + 32 + 32 + 65;

    if (*output_len < required_len) {
        return 0;
    }

    unsigned char *cursor = output;
    *cursor = nizkp->generator_index;
    cursor += 1;

    memcpy(cursor, nizkp->u, 65);
    cursor += 65;
    memcpy(cursor, nizkp->c, 32);
    cursor += 32;
    memcpy(cursor, nizkp->z, 32);
    cursor += 32;
    memcpy(cursor, nizkp->h, 65);
    cursor += 65;

    *output_len = required_len;

    return 1;
}

int secp256r1_nizkp_parse(
        secp256r1_nizkp *nizkp,
        const unsigned char *input,
        uint32_t input_len
) {
    uint32_t expected_len = 1 + 65 + 32 + 32 + 65;

    if (input_len != expected_len) {
        return 0;
    }

    const unsigned char *cursor = input;
    nizkp->generator_index = *cursor;
    cursor += 1;
    memcpy(nizkp->u, cursor, 65);
    cursor += 65;
    memcpy(nizkp->c, cursor, 32);
    cursor += 32;
    memcpy(nizkp->z, cursor, 32);
    cursor += 32;
    memcpy(nizkp->h, cursor, 65);
    cursor += 65;

    return 1;
}

int secp256r1_recovery_packet_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const secp256r1_keygen_recovery_packet *packet
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


    if (!secp256r1_nizkp_serialize(cursor, &nizkp_1_len, &(packet->nizkp_y_3i))) {
        return 0;
    }
    cursor += nizkp_1_len;
    bytes_written += nizkp_1_len;

    remaining_space = total_space - bytes_written;
    uint32_t nizkp_2_len = remaining_space;


    if (!secp256r1_nizkp_serialize(cursor, &nizkp_2_len, &(packet->nizkp_y_i3))) {
        return 0;
    }
    bytes_written += nizkp_2_len;
    *output_len = bytes_written;

    return 1;
}

int secp256r1_recovery_packet_parse(
        secp256r1_keygen_recovery_packet *packet,
        const unsigned char *input,
        uint32_t input_len
) {
    uint32_t expected_nizkp_len = 1 + 65 + 32 + 32 + 65;
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

    if (!secp256r1_nizkp_parse(&(packet->nizkp_y_3i), cursor, expected_nizkp_len)) {
        return 0;
    }
    cursor += expected_nizkp_len;

    if (!secp256r1_nizkp_parse(&(packet->nizkp_y_i3), cursor, expected_nizkp_len)) {
        return 0;
    }

    return 1;
}

int secp256r1_keygen_shamir_secret_share_serialize(
        unsigned char *output,
        const secp256r1_keygen_shamir_secret_share *share
) {
    unsigned char *cursor = output;
    *cursor = share->generator_index;
    cursor += 1;
    *cursor = share->receiver_index;
    cursor += 1;
    memcpy(cursor, share->value, 32);
    return 1;
}

int secp256r1_keygen_shamir_secret_share_parse(
        secp256r1_keygen_shamir_secret_share *share,
        const unsigned char *input
) {
    const unsigned char *cursor = input;
    share->generator_index = *cursor;
    cursor += 1;
    share->receiver_index = *cursor;
    cursor += 1;
    memcpy(share->value, cursor, 32);
    return 1;
}

int secp256r1_schnorr_pubkey_parse(
        secp256r1_schnorr_pubkey *pubkey,
        const unsigned char *input,
        uint8_t inputlen
) {
    if (inputlen != 65) {
        return 0;
    }
    if (input[0] != 0x04) {
        return 0;
    }
    memcpy(pubkey->point.value, input, 65);
    pubkey->point.generator_index = 0;

    return 1;
}

int secp256r1_schnorr_pubkey_serialize(
        unsigned char *output,
        uint8_t *outputlen,
        const secp256r1_schnorr_pubkey *pubkey
) {
    if (*outputlen < 65) {
        return 0;
    }
    memcpy(output, pubkey->point.value, 65);
    *outputlen = 65;
    return 1;
}

int secp256r1_commit_point(
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_point_extended *point,
        const uint16_t dsc,
        CSPRNG_STATE_T *csprng_state
) {
    secp256r1_private_secret_scalar nonce;
    nonce.generator_index = point->generator_index;
    int valid = 0;

    while (!valid) {
        csprng_randombytes(nonce.value, 32, csprng_state);
        if (secp256r1_scalar_verify(&nonce)) {
            valid = 1;
        }
    }

    unsigned char m[80];
    unsigned char *m_cursor = m;

    uint64_t x_len_le = 32;
    memcpy(m_cursor, &x_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, &(point->value[1]), 32);
    m_cursor += 32;

    uint64_t y_len_le = 32;
    memcpy(m_cursor, &y_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, &(point->value[33]), 32);

    unsigned char hash_digest[32];
    uint8_t counter = 1;

    hash(hash_digest, nonce.value, m, 80, dsc, counter);

    commitment_packet->generator_index = point->generator_index;
    memcpy(commitment_packet->commitment.data, hash_digest, 32);
    memcpy(commitment_packet->decommitment.nonce, nonce.value, 32);

    if (65 > SECP256R1_MAX_COMMITMENT_SIZE) {
        return 0;
    }
    memcpy(commitment_packet->decommitment.value, point->value, 65);
    commitment_packet->decommitment.value_len = 65;

    return 1;
}

int secp256r1_commit_scalar(
        secp256r1_commitment_packet *commitment_packet,
        const secp256r1_private_secret_scalar *scalar,
        const uint16_t dsc,
        CSPRNG_STATE_T *csprng_state
) {
    secp256r1_private_secret_scalar nonce;
    nonce.generator_index = scalar->generator_index;
    int valid = 0;

    while (!valid) {
        csprng_randombytes(nonce.value, 32, csprng_state);
        if (secp256r1_scalar_verify(&nonce)) {
            valid = 1;
        }
    }

    unsigned char m[40];
    unsigned char *m_cursor = m;

    uint64_t value_len_le = 32;
    memcpy(m_cursor, &value_len_le, 8);
    m_cursor += 8;
    memcpy(m_cursor, scalar->value, 32);

    unsigned char hash_digest[32];
    uint8_t counter = 1;
    hash(hash_digest, nonce.value, m, 40, dsc, counter);

    commitment_packet->generator_index = scalar->generator_index;
    memcpy(commitment_packet->commitment.data, hash_digest, 32);
    memcpy(commitment_packet->decommitment.nonce, nonce.value, 32);

    if (32 > SECP256R1_MAX_COMMITMENT_SIZE) {
        return 0; //
    }

    memcpy(commitment_packet->decommitment.value, scalar->value, 32);
    commitment_packet->decommitment.value_len = 32;

    return 1;
}

int secp256r1_rejection_sampling_q(const unsigned char *scalar) {
    if (memcmp(scalar, secp256r1_zero, 32) == 0) {
        return 0;
    }
    if (memcmp(scalar, secp256r1_one, 32) == 0) {
        return 0;
    }
    if (memcmp(scalar, secp256r1_q_minus_one, 32) == 0) {
        return 0;
    }
    if (memcmp(scalar, secp256r1_q, 32) == 0) {
        return 0;
    }

    for (int i = 0; i < 32; i++) {
        if (scalar[i] > secp256r1_q[i]) {
            return 0;
        }
        if (scalar[i] < secp256r1_q[i]) {
            break;
        }
    }

    return 1;
}