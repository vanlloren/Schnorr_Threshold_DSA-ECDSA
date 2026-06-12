//
// Created by PC on 22/05/2026.
//

#include <string.h>
#include <stdio.h>
#include "schnorr.h"
#include "utils.h"
#include "secp256r1_rsakeys.h"
#include "dsc_values.h"
#include "rng.h"
#include "scalar_op.h"
#include "EC_arithmetics.h"
#if SECURITY_LEVEL == 128
    #include "secp256r1_curve_params.h"
#elif SECURITY_LEVEL == 256
    #include "secp521r1_curve_params.h"
#endif

// Funzione di supporto per stampare un array di byte in formato HEX
static inline void print_hex3(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int commitment_serialize(
        unsigned char *output,
        const commitment *commit
) {
    memcpy(output, commit->data, COMMITMENT_BUFFER_SIZE);
    return 1;
}

int commitment_parse(
        commitment *commit,
        const unsigned char *input
) {
    memcpy(commit->data, input, COMMITMENT_BUFFER_SIZE);
    return 1;
}

int decommitment_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const decommitment *decommit
) {
    uint32_t required_space = SCALAR_SIZE + decommit->value_len + sizeof(uint32_t);

    if (*output_len < required_space) {
        return 0;
    }

    unsigned char *cursor = output;

    memcpy(cursor, decommit->nonce, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(cursor, decommit->value, decommit->value_len);
    cursor += decommit->value_len;
    uint32_t val_len_encoded = (uint32_t)decommit->value_len;
    memcpy(cursor, &val_len_encoded, sizeof(uint32_t));
    *output_len = required_space;

    return 1;
}

int decommitment_parse(
        decommitment *decommit,
        const unsigned char *input,
        uint32_t input_len
) {
    if (input_len < (SCALAR_SIZE + sizeof(uint32_t))) {
        return 0;
    }

    uint32_t extracted_val_len;
    const unsigned char *len_ptr = input + (input_len - sizeof(uint32_t));
    memcpy(&extracted_val_len, len_ptr, sizeof(uint32_t));

    if (extracted_val_len > MAX_COMMITMENT_SIZE) {
        return 0;
    }

    uint32_t expected_total_len = SCALAR_SIZE + extracted_val_len + sizeof(uint32_t);
    if (input_len != expected_total_len) {
        return 0;
    }

    const unsigned char *cursor = input;

    memcpy(decommit->nonce, cursor, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(decommit->value, cursor, extracted_val_len);
    decommit->value_len = (uint8_t)extracted_val_len;

    return 1;
}

int keygen_recovery_info_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const keygen_recovery_info *recovery_info
) {
    uint32_t total_space = *output_len;
    uint32_t bytes_written = 0;
    unsigned char *cursor = output;

    // La dimensione corretta richiesta è: 1 + 34 (la share) + RECOVERY_PACKET_SIZE
    // Sostituiamo il calcolo manuale con una logica dinamica
    uint32_t share_len = 1 + 1 + SCALAR_SIZE; // 34 byte
    if (total_space < 1 + share_len + RECOVERY_PACKET_SIZE) {
        return 0;
    }

    // 1. Scrittura generator_index di livello 0
    *cursor = recovery_info->generator_index;
    cursor += 1;
    bytes_written += 1;

    // 2. Scrittura Shamir Secret Share
    if (!keygen_shamir_secret_share_serialize(cursor, &(recovery_info->share_i_j))) {
        return 0;
    }
    // AVANZAMENTO CORRETTO: la share occupa 1 (gen) + 1 (recv) + SCALAR_SIZE
    cursor += share_len;
    bytes_written += share_len;

    // 3. Scrittura Recovery Packet
    uint32_t remaining_space = total_space - bytes_written;
    uint32_t packet_written_len = remaining_space;

    if (!recovery_packet_serialize(cursor, &packet_written_len, &(recovery_info->recovery_packet))) {
        return 0;
    }

    bytes_written += packet_written_len;
    *output_len = bytes_written;

    return 1;
}

int keygen_recovery_info_parse(
        keygen_recovery_info *recovery_info,
        const unsigned char *input,
        uint32_t input_len
) {
    uint32_t share_len = 1 + 1 + SCALAR_SIZE; // 34 byte
    if (input_len < 1 + share_len + RECOVERY_PACKET_SIZE) {
        return 0;
    }

    const unsigned char *cursor = input;

    // 1. Lettura generator_index di livello 0
    recovery_info->generator_index = *cursor;
    cursor += 1;

    // 2. Lettura Shamir Secret Share
    if (!keygen_shamir_secret_share_parse(&(recovery_info->share_i_j), cursor)) {
        return 0;
    }
    // AVANZAMENTO CORRETTO: deve essere identico a quello della serializzazione
    cursor += share_len;

    // 3. Lettura Recovery Packet
    uint32_t bytes_read_so_far = cursor - input;
    uint32_t remaining_input_len = input_len - bytes_read_so_far;

    if (!recovery_packet_parse(&(recovery_info->recovery_packet), cursor, remaining_input_len)) {
        return 0;
    }

    return 1;
}

int signature_recovery_info_serialize(
        unsigned char *output,
        uint32_t *output_len,
        const signature_recovery_info *recovery_info
) {
    uint32_t total_space = *output_len;
    uint32_t bytes_written = 0;
    unsigned char *cursor = output;

    if (total_space < POINT_SIZE + 1 + 2 * RECOVERY_PACKET_SIZE) {
        return 0;
    }

    *cursor = recovery_info->pubkey.point.generator_index;
    cursor += 1;
    bytes_written += 1;

    memcpy(cursor, recovery_info->pubkey.point.value, POINT_SIZE);
    cursor += POINT_SIZE;
    bytes_written += POINT_SIZE;

    uint32_t remaining_space = total_space - bytes_written;
    uint32_t packet_1_written_len = remaining_space;

    if (!recovery_packet_serialize(cursor, &packet_1_written_len, &(recovery_info->recovery_packet_1_3))) {
        return 0;
    }
    cursor += packet_1_written_len;
    bytes_written += packet_1_written_len;

    remaining_space = total_space - bytes_written;
    uint32_t packet_2_written_len = remaining_space;

    if (!recovery_packet_serialize(cursor, &packet_2_written_len, &(recovery_info->recovery_packet_2_3))) {
        return 0;
    }
    bytes_written += packet_2_written_len;

    *output_len = bytes_written;

    return 1;
}

int signature_recovery_info_parse(
        signature_recovery_info *recovery_info,
        const unsigned char *input,
        uint32_t input_len
) {
    if (input_len < POINT_SIZE + 1 + 2 * RECOVERY_PACKET_SIZE) {
        return 0;
    }

    const unsigned char *cursor = input;

    recovery_info->pubkey.point.generator_index = *cursor;
    cursor += 1;

    memcpy(recovery_info->pubkey.point.value, cursor, POINT_SIZE);
    cursor += POINT_SIZE;

    uint32_t remaining_input_len = input_len - (POINT_SIZE + 1);

    if (remaining_input_len < RECOVERY_PACKET_SIZE) {
        return 0;
    }

    if (!recovery_packet_parse(&(recovery_info->recovery_packet_1_3), cursor, RECOVERY_PACKET_SIZE)) {
        return 0;
    }
    cursor += RECOVERY_PACKET_SIZE;
    remaining_input_len -= RECOVERY_PACKET_SIZE;

    if (!recovery_packet_parse(&(recovery_info->recovery_packet_2_3), cursor, remaining_input_len)) {
        return 0;
    }

    return 1;
}

int point_extended_serialize(
        unsigned char *output,
        const point_extended *point
) {
    unsigned char *cursor = output;

    *cursor = point->generator_index;
    cursor += 1;
    memcpy(cursor, point->value, POINT_SIZE);

    return 1;
}

int point_extended_parse(
        point_extended *point,
        const unsigned char *input
) {
    const unsigned char *cursor = input;

    point->generator_index = *cursor;
    cursor += 1;
    memcpy(point->value, cursor, POINT_SIZE);

    return 1;
}

int private_scalar_serialize(
        unsigned char *output,
        const private_secret_scalar *scalar
) {
    unsigned char *cursor = output;

    *cursor = scalar->generator_index;
    cursor += 1;
    memcpy(cursor, scalar->value, SCALAR_SIZE);

    return 1;
}

int private_scalar_parse(
        private_secret_scalar *scalar,
        const unsigned char *input
) {
    const unsigned char *cursor = input;

    scalar->generator_index = *cursor;
    cursor += 1;
    memcpy(scalar->value, cursor, SCALAR_SIZE);

    return 1;
}

int schnorr_keygen_phase1(
        private_secret_scalar *sec_scalar_array,
        keygen_shamir_secret_share *sam_sec_share,
        point_extended *ec_points_array,
        commitment_packet *commitment_packets,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
) {
    // Initialize CSPRNG
    unsigned char seed[32];
    if (!collect_random_seed(seed)){
        return 0;
    }
    csprng_initialize(csprng_state, seed, 32, DSC_CSPRNG_INIT);

    // seed reset
    memset(seed, 0, sizeof(seed));

    // Generate random scalars a_i, m_i and shamir secret share y_{3_i}
    // set a_i and m_i generator index to generator_index
    for (int i = 0; i < 2; i++) {
        sec_scalar_array[i].generator_index = generator_index;
    }
    // set y_{3_i} generator index to generator_index and receiver index
    sam_sec_share->generator_index = generator_index;
    if(generator_index == 1){
        sam_sec_share->receiver_index = 2;
    } else if(generator_index == 2){
        sam_sec_share->receiver_index = 1;
    } else {
        return 0;
    }

    do {
        csprng_randombytes(sec_scalar_array[0].value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(sec_scalar_array[0].value, SCALAR_SIZE));

    do {
        csprng_randombytes(sec_scalar_array[1].value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(sec_scalar_array[1].value, SCALAR_SIZE));

    do {
        csprng_randombytes(sam_sec_share->value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(sam_sec_share->value, SCALAR_SIZE));

    // Compute EC point A_i = a_i * G
    point_gej temp_point_gej;
    point_ge temp_point_ge;
    if (!point_gej_scalar_mult_base(&temp_point_gej, &sec_scalar_array[0])) {
        return 0;
    }
    if(!point_gej_to_ge(&temp_point_ge, &temp_point_gej)){
        return 0;
    }
    if (!point_ge_serialize(&ec_points_array[0], &temp_point_ge)) {
        return 0;
    }

    // Compute EC point Y_{3_i} = y_{3_i} * G
    point_gej temp_point_gej_y_3_i;
    point_ge temp_point_ge_y_3_i;
    private_secret_scalar y_3_i_scalar;
    y_3_i_scalar.generator_index = generator_index;
    memcpy(y_3_i_scalar.value, sam_sec_share->value, SCALAR_SIZE);
    if(!point_gej_scalar_mult_base(&temp_point_gej_y_3_i, &y_3_i_scalar)){
        return 0;
    }
    if(!point_gej_to_ge(&temp_point_ge_y_3_i, &temp_point_gej_y_3_i)){
        return 0;
    }
    if (!point_ge_serialize(&ec_points_array[1], &temp_point_ge_y_3_i)) {
        return 0;
    }

    // Compute commitment packet for each EC point
    for (int i = 0; i < 2; i++) {
        if (!commit_point(&commitment_packets[i], &ec_points_array[i], DSC_KEYGEN_COMMIT, csprng_state)) {
            return 0;
        }
    }

    return 1;
}

int schnorr_keygen_phase2(
        keygen_shamir_secret_share *sam_sec_share_array,
        point_extended *M_i,
        keygen_recovery_packet *recovery_packet,
        const private_secret_scalar *sec_scalar_array,
        const keygen_shamir_secret_share *sam_sec_share_y_3_i,
        const EVP_PKEY *enc_pubkey,
        uint8_t generator_index
){
    // evaluate shamir polynomial
    private_secret_scalar shamir_evaluation;

    for(int i = 0; i <= 2; i++){
        memset(shamir_evaluation.value, 0, SCALAR_SIZE);
        if (i == 0) {
            if (!scalar_add(&shamir_evaluation, &sec_scalar_array[0], &sec_scalar_array[1])) {
                return 0;
            }
        } else if (i == 1) {
            if (!scalar_add(&shamir_evaluation, &sec_scalar_array[0], &sec_scalar_array[1])) {
                return 0;
            }
            if (!scalar_add(&shamir_evaluation, &shamir_evaluation, &sec_scalar_array[1])) {
                return 0;
            }
        } else if (i == 2) {
            if (!scalar_add(&shamir_evaluation, &sec_scalar_array[0], &sec_scalar_array[1])) {
                return 0;
            }
            if (!scalar_add(&shamir_evaluation, &shamir_evaluation, &sec_scalar_array[1])) {
                return 0;
            }
            if (!scalar_add(&shamir_evaluation, &shamir_evaluation, &sec_scalar_array[1])) {
                return 0;
            }
        }

        memcpy(sam_sec_share_array[i].value, shamir_evaluation.value, SCALAR_SIZE);
        sam_sec_share_array[i].generator_index = generator_index;
        sam_sec_share_array[i].receiver_index = i+1;
    }

    // compute M_i = m_i * G
    point_gej temp_point_gej;
    point_ge temp_point_ge;

    if (!point_gej_scalar_mult_base(&temp_point_gej, &sec_scalar_array[1])) {
        return 0;
    }
    if (!point_gej_to_ge(&temp_point_ge, &temp_point_gej)) {
        return 0;
    }
    if(!point_ge_serialize(M_i, &temp_point_ge)){
        return 0;
    }

    // Encrypt Shamir shares for recovery party
    unsigned char ciphertext[RSA_CIPHERTEXT_SIZE];
    recovery_packet->generator_index = generator_index;

    size_t encrypted_len1 = RSA_CIPHERTEXT_SIZE;
    if (!secp256r1_rsa_encrypt(ciphertext, enc_pubkey, sam_sec_share_y_3_i->value, &encrypted_len1)) {
        return 0;
    }
    memcpy(recovery_packet->encrypted_y_3i, ciphertext, RSA_CIPHERTEXT_SIZE);

    memset(ciphertext, 0, RSA_CIPHERTEXT_SIZE);

    size_t encrypted_len2 = RSA_CIPHERTEXT_SIZE;
    if (!secp256r1_rsa_encrypt(ciphertext, enc_pubkey, sam_sec_share_array[2].value, &encrypted_len2)) {
        return 0;
    }
    memcpy(recovery_packet->encrypted_y_i3, ciphertext, RSA_CIPHERTEXT_SIZE);
    memset(ciphertext, 0, RSA_CIPHERTEXT_SIZE);

    return 1;
}

int schnorr_keygen_compute_nizkps(
        keygen_recovery_packet *recovery_packet,
        keygen_shamir_secret_share *sam_sec_share_array,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
){
    // generate a random scalar nonce
    private_secret_scalar nonce1;
    private_secret_scalar nonce2;
    do {
        csprng_randombytes(nonce1.value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(nonce1.value, SCALAR_SIZE));

    do {
        csprng_randombytes(nonce2.value, SCALAR_SIZE, csprng_state);
    } while(!rejection_sampling_q(nonce2.value, SCALAR_SIZE));

    // convert y_{i_3} and y_{3_i} to points H1 and H2
    point_extended h1;
    point_extended h2;
    point_gej temp_point_gej;
    point_ge temp_point_ge;
    private_secret_scalar y_i_3_scalar;
    private_secret_scalar y_3_i_scalar;
    y_i_3_scalar.generator_index = sam_sec_share_array[0].generator_index;
    y_3_i_scalar.generator_index = sam_sec_share_array[1].generator_index;
    memcpy(y_i_3_scalar.value, sam_sec_share_array[0].value, SCALAR_SIZE);
    memcpy(y_3_i_scalar.value, sam_sec_share_array[1].value, SCALAR_SIZE);

    if (!point_gej_scalar_mult_base(&temp_point_gej, &y_i_3_scalar)) {
        return 0;
    }
    if (!point_gej_to_ge(&temp_point_ge, &temp_point_gej)) {
        return 0;
    }
    if (!point_ge_serialize(&h1, &temp_point_ge)) {
        return 0;
    }
    memset(&temp_point_gej, 0, sizeof(temp_point_gej));
    memset(&temp_point_ge, 0, sizeof(temp_point_ge));

    if (!point_gej_scalar_mult_base(&temp_point_gej, &y_3_i_scalar)) {
        return 0;
    }
    if (!point_gej_to_ge(&temp_point_ge, &temp_point_gej)) {
        return 0;
    }
    if (!point_ge_serialize(&h2, &temp_point_ge)) {
        return 0;
    }

    // compute u1 and u2
    point_extended u1;
    point_extended u2;
    point_gej temp_u1_gej;
    point_ge temp_u1_ge;
    point_gej temp_u2_gej;
    point_ge temp_u2_ge;

    if (!point_gej_scalar_mult_base(&temp_u1_gej, &nonce1)) {
        return 0;
    }
    if (!point_gej_to_ge(&temp_u1_ge, &temp_u1_gej)) {
        return 0;
    }
    if (!point_ge_serialize(&u1, &temp_u1_ge)) {
        return 0;
    }
    if (!point_gej_scalar_mult_base(&temp_u2_gej, &nonce2)) {
        return 0;
    }
    if (!point_gej_to_ge(&temp_u2_ge, &temp_u2_gej)) {
        return 0;
    }
    if (!point_ge_serialize(&u2, &temp_u2_ge)) {
        return 0;
    }

    // compute message1 as len(g) || g.x || g.y || len(q) || q || len(h1) || h1.x || h1.y || len(u1) || u1.x || u1.y
    // 8bytes + 66 + 66 + 8 + 32 + 8 + 66 + 66 + 8 + 66 + 66
    uint16_t dim;
    dim = 8 + SCALAR_SIZE*2 + 8 + SCALAR_SIZE + 8 + SCALAR_SIZE*2 + 8 + SCALAR_SIZE*2;
    unsigned char message1[dim];
    unsigned char *cursor = message1;

    uint64_t len_g = POINT_SIZE-1;
    memcpy(cursor, &len_g, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &G[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_q = SCALAR_SIZE;
    memcpy(cursor, &len_q, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, q, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    uint64_t len_h1 = POINT_SIZE-1;
    memcpy(cursor, &len_h1, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &h1.value[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_u1 = POINT_SIZE-1;
    memcpy(cursor, &len_u1, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &u1.value[1], POINT_SIZE-1);

    // compute message2 as len(g) || g.x || g.y || len(q) || q || len(h2) || h2.x || h2.y || len(u2) || u2.x || u2.y
    unsigned char message2[dim];
    cursor = message2;
    uint64_t len_h2 = POINT_SIZE-1;
    memcpy(cursor, &len_g, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &G[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    memcpy(cursor, &len_q, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, q, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(cursor, &len_h2, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &h2.value[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_u2 = POINT_SIZE-1;
    memcpy(cursor, &len_u2, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &u2.value[1], POINT_SIZE-1);

    // compute c1 and c2
    uint8_t c1[SCALAR_SIZE];
    uint8_t c2[SCALAR_SIZE];
    memset(c1, 0, SCALAR_SIZE);
    memset(c2, 0, SCALAR_SIZE);

    // perform hash until digest is modulo q
    uint8_t counter = 0;
    do{
        hash_plain(&c1[SCALAR_SIZE-HASH_DIGEST_LENGTH], message1, dim, DSC_NIZKP_HASH, counter);
        counter++;
    } while (!rejection_sampling_q(c1, SCALAR_SIZE));

    counter = 0;
    do{
        hash_plain(&c2[SCALAR_SIZE-HASH_DIGEST_LENGTH], message2, dim, DSC_NIZKP_HASH, counter);
        counter++;
    } while (!rejection_sampling_q(c2, SCALAR_SIZE));

    // compute z1 and z2
    private_secret_scalar z1;
    private_secret_scalar z2;

    // load c1 and c2 into scalars
    private_secret_scalar c1_scalar;
    private_secret_scalar c2_scalar;
    c1_scalar.generator_index = generator_index;
    c2_scalar.generator_index = generator_index;
    memcpy(c1_scalar.value, c1, SCALAR_SIZE);
    memcpy(c2_scalar.value, c2, SCALAR_SIZE);

    // compute z1 = nonce1 + c1 * y_{i_3}
    if (!scalar_mult(&z1, &c1_scalar, &y_i_3_scalar)) {
        return 0;
    }
    if (!scalar_add(&z1, &z1, &nonce1)) {
        return 0;
    }
    // compute z2 = nonce2 + c2 * y_{3_i}
    if (!scalar_mult(&z2, &c2_scalar, &y_3_i_scalar)) {
        return 0;
    }
    if (!scalar_add(&z2, &z2, &nonce2)) {
        return 0;
    }

    // fill nizkp packet
    recovery_packet->nizkp_y_3i.generator_index = generator_index;
    memcpy(recovery_packet->nizkp_y_3i.c, c2, SCALAR_SIZE);
    memcpy(recovery_packet->nizkp_y_3i.z, z2.value, SCALAR_SIZE);
    memcpy(recovery_packet->nizkp_y_3i.h, h2.value, POINT_SIZE);
    memcpy(recovery_packet->nizkp_y_3i.u, u2.value, POINT_SIZE);

    recovery_packet->nizkp_y_i3.generator_index = generator_index;
    memcpy(recovery_packet->nizkp_y_i3.c, c1, SCALAR_SIZE);
    memcpy(recovery_packet->nizkp_y_i3.z, z1.value, SCALAR_SIZE);
    memcpy(recovery_packet->nizkp_y_i3.h, h1.value, POINT_SIZE);
    memcpy(recovery_packet->nizkp_y_i3.u, u1.value, POINT_SIZE);

    return 1;
}

int schnorr_keygen_verify_nizkps(
        const keygen_recovery_packet *recovery_packet
){
    // check that u1, u2, h1, h2 are not point at infinity
    point_gej temp_point_gej_u1;
    point_gej temp_point_gej_u2;
    point_gej temp_point_gej_h1;
    point_gej temp_point_gej_h2;
    point_ge temp_point_ge;

    point_extended temp_point_extended_u1;
    point_extended temp_point_extended_u2;
    point_extended temp_point_extended_h1;
    point_extended temp_point_extended_h2;

    // parse points from recovery packet to point_extended
    temp_point_extended_u1.generator_index = recovery_packet->nizkp_y_i3.generator_index;
    memcpy(temp_point_extended_u1.value, recovery_packet->nizkp_y_i3.u, POINT_SIZE);
    temp_point_extended_h1.generator_index = recovery_packet->nizkp_y_i3.generator_index;
    memcpy(temp_point_extended_h1.value, recovery_packet->nizkp_y_i3.h, POINT_SIZE);
    temp_point_extended_u2.generator_index = recovery_packet->nizkp_y_3i.generator_index;
    memcpy(temp_point_extended_u2.value, recovery_packet->nizkp_y_3i.u, POINT_SIZE);
    temp_point_extended_h2.generator_index = recovery_packet->nizkp_y_3i.generator_index;
    memcpy(temp_point_extended_h2.value, recovery_packet->nizkp_y_3i.h, POINT_SIZE);

    //parse scalars from recovery packet to private_secret_scalar
    private_secret_scalar temp_scalar_c1;
    private_secret_scalar temp_scalar_c2;
    private_secret_scalar temp_scalar_z1;
    private_secret_scalar temp_scalar_z2;

    temp_scalar_c1.generator_index = recovery_packet->nizkp_y_i3.generator_index;
    memcpy(temp_scalar_c1.value, recovery_packet->nizkp_y_i3.c, SCALAR_SIZE);
    temp_scalar_z1.generator_index = recovery_packet->nizkp_y_i3.generator_index;
    memcpy(temp_scalar_z1.value, recovery_packet->nizkp_y_i3.z, SCALAR_SIZE);
    temp_scalar_c2.generator_index = recovery_packet->nizkp_y_3i.generator_index;
    memcpy(temp_scalar_c2.value, recovery_packet->nizkp_y_3i.c, SCALAR_SIZE);
    temp_scalar_z2.generator_index = recovery_packet->nizkp_y_3i.generator_index;
    memcpy(temp_scalar_z2.value, recovery_packet->nizkp_y_3i.z, SCALAR_SIZE);

    if(!point_ge_parse(&temp_point_ge, &temp_point_extended_u1)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_u1, &temp_point_ge)){
        return 0;
    }
    memset(&temp_point_ge, 0, sizeof(temp_point_ge));
    if(!point_ge_parse(&temp_point_ge, &temp_point_extended_u2)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_u2, &temp_point_ge)){
        return 0;
    }
    memset(&temp_point_ge, 0, sizeof(temp_point_ge));
    if(!point_ge_parse(&temp_point_ge, &temp_point_extended_h1)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_h1, &temp_point_ge)){
        return 0;
    }
    memset(&temp_point_ge, 0, sizeof(temp_point_ge));
    if(!point_ge_parse(&temp_point_ge, &temp_point_extended_h2)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_h2, &temp_point_ge)){
        return 0;
    }

    //check infinity
    if (point_gej_is_infinity(&temp_point_gej_u1) || point_gej_is_infinity(&temp_point_gej_u2) ||
        point_gej_is_infinity(&temp_point_gej_h1) || point_gej_is_infinity(&temp_point_gej_h2)) {
        return 0;
    }

    //check validity
    if(!point_gej_is_valid(&temp_point_gej_u1) || !point_gej_is_valid(&temp_point_gej_u2) ||
       !point_gej_is_valid(&temp_point_gej_h1) || !point_gej_is_valid(&temp_point_gej_h2)){
        return 0;
    }

    // check if z1 = 0 or z2 = 0 mod q
    if(scalar_is_zero(&temp_scalar_z1) || scalar_is_zero(&temp_scalar_z2)){
        return 0;
    }

    // compare c1 and c2 with recomputed values
    // recompute message1 and message2
    uint16_t dim;
    dim = 8 + SCALAR_SIZE*2 + 8 + SCALAR_SIZE + 8 + SCALAR_SIZE*2 + 8 + SCALAR_SIZE*2;
    unsigned char message1[dim];
    unsigned char *cursor = message1;

    uint64_t len_g = POINT_SIZE-1;
    memcpy(cursor, &len_g, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &G[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_q = SCALAR_SIZE;
    memcpy(cursor, &len_q, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, q, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    uint64_t len_h1 = POINT_SIZE-1;
    memcpy(cursor, &len_h1, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &recovery_packet->nizkp_y_i3.h[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_u1 = POINT_SIZE-1;
    memcpy(cursor, &len_u1, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &recovery_packet->nizkp_y_i3.u[1], POINT_SIZE-1);

    unsigned char message2[dim];
    cursor = message2;
    uint64_t len_h2 = POINT_SIZE-1;
    memcpy(cursor, &len_g, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &G[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    memcpy(cursor, &len_q, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, q, SCALAR_SIZE);
    cursor += SCALAR_SIZE;
    memcpy(cursor, &len_h2, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &recovery_packet->nizkp_y_3i.h[1], POINT_SIZE-1);
    cursor += POINT_SIZE-1;
    uint64_t len_u2 = POINT_SIZE-1;
    memcpy(cursor, &len_u2, sizeof(uint64_t));
    cursor += sizeof(uint64_t);
    memcpy(cursor, &recovery_packet->nizkp_y_3i.u[1], POINT_SIZE-1);

    // recompute c1 and c2
    uint8_t recomputed_c1[SCALAR_SIZE];
    uint8_t recomputed_c2[SCALAR_SIZE];
    memset(recomputed_c1, 0, SCALAR_SIZE);
    memset(recomputed_c2, 0, SCALAR_SIZE);

    uint8_t counter = 0;
    do {
        hash_plain(&recomputed_c1[SCALAR_SIZE-HASH_DIGEST_LENGTH], message1, dim, DSC_NIZKP_HASH, counter);
        counter++;
    } while (!rejection_sampling_q(recomputed_c1, SCALAR_SIZE));

    counter = 0;
    do {
        hash_plain(&recomputed_c2[SCALAR_SIZE-HASH_DIGEST_LENGTH], message2, dim, DSC_NIZKP_HASH, counter);
        counter++;
    } while (!rejection_sampling_q(recomputed_c2, SCALAR_SIZE));

    if (memcmp(recomputed_c1, recovery_packet->nizkp_y_i3.c, SCALAR_SIZE) != 0 || memcmp(recomputed_c2, recovery_packet->nizkp_y_3i.c, SCALAR_SIZE) != 0) {
        return -1;
    }

    // compute z1 * G and z2 * G
    point_gej temp_z1G_gej;
    point_gej temp_z2G_gej;

    if (!point_gej_scalar_mult_base(&temp_z1G_gej, &temp_scalar_z1)) {
        return 0;
    }
    if (!point_gej_scalar_mult_base(&temp_z2G_gej, &temp_scalar_z2)) {
        return 0;
    }

    //compute u1 + c1 * h1 and u2 + c2 * h2
    point_gej temp_c1h1_gej;
    point_gej temp_c2h2_gej;
    point_gej temp_u1_plus_c1h1_gej;
    point_gej temp_u2_plus_c2h2_gej;

    private_secret_scalar c1_scalar;
    c1_scalar.generator_index = recovery_packet->nizkp_y_i3.generator_index;
    memcpy(c1_scalar.value, recovery_packet->nizkp_y_i3.c, SCALAR_SIZE);
    if (!point_gej_scalar_mult(&temp_c1h1_gej, &temp_point_gej_h1, &c1_scalar)) {
        return 0;
    }
    if (!point_gej_add(&temp_u1_plus_c1h1_gej, &temp_point_gej_u1, &temp_c1h1_gej)) {
        return 0;
    }

    private_secret_scalar c2_scalar;
    c2_scalar.generator_index = recovery_packet->nizkp_y_3i.generator_index;
    memcpy(c2_scalar.value, recovery_packet->nizkp_y_3i.c, SCALAR_SIZE);
    if (!point_gej_scalar_mult(&temp_c2h2_gej, &temp_point_gej_h2, &c2_scalar)) {
        return 0;
    }
    if (!point_gej_add(&temp_u2_plus_c2h2_gej, &temp_point_gej_u2, &temp_c2h2_gej)) {
        return 0;
    }

    // check if z1 * G == u1 + c1 * h1 and z2 * G == u2 + c2 * h2
    if (!point_gej_equal(&temp_z1G_gej, &temp_u1_plus_c1h1_gej) || !point_gej_equal(&temp_z2G_gej, &temp_u2_plus_c2h2_gej)) {
        return -1;
    }

    return 1;
}

int schnorr_keygen_verify_public_shares(
        const keygen_shamir_secret_share *y_j_i,
        const point_extended *M_j,
        const point_extended *A_j,
        uint8_t generator_index
){
    private_secret_scalar y_j_i_scalar;

    // copy y_j_i to y_j_i_point
    y_j_i_scalar.generator_index = y_j_i->generator_index;
    memcpy(y_j_i_scalar.value, y_j_i->value, SCALAR_SIZE);

    // compute y_j_i * G
    point_gej temp_y_j_i_G_gej;
    if(!point_gej_scalar_mult_base(&temp_y_j_i_G_gej, &y_j_i_scalar)){
        return 0;
    }

    // compute A_j + (M_j * other_generator_index)
    point_ge temp_A_j_ge;
    point_gej temp_M_j_gej;
    point_ge temp_M_j_ge;

    if(!point_ge_parse(&temp_A_j_ge, A_j)){
        return 0;
    }

    if(!point_ge_parse(&temp_M_j_ge, M_j)){
        return 0;
    }
    if (!point_ge_to_gej(&temp_M_j_gej, &temp_M_j_ge)) {
        return 0;
    }

    // compute (M_j * other_generator_index)
    if(generator_index == 2) {
        // other_generator_index is 1, so we compute M_j * 2
        if (!point_gej_add(&temp_M_j_gej, &temp_M_j_gej, &temp_M_j_gej)) {
            return 0;
        }
    } else if(generator_index != 1) {
        return 0;
    }

    // compute A_j + (M_j * other_generator_index)
    point_gej temp_A_j_plus_M_j_gej;
    point_gej temp_A_j_gej;

    if(!point_ge_to_gej(&temp_A_j_gej, &temp_A_j_ge)){
        return 0;
    }
    if (!point_gej_add(&temp_A_j_plus_M_j_gej, &temp_A_j_gej, &temp_M_j_gej)) {
        return 0;
    }

    // compare y_j_i * G with A_j + (M_j * other_generator_index)
    if(!point_gej_equal(&temp_y_j_i_G_gej, &temp_A_j_plus_M_j_gej)) {
        return -1;
    }

    return 1;
}

int schnorr_keygen_generate_seckey(
        schnorr_seckey *schnorr_seckey_sig,
        schnorr_seckey *schnorr_seckey_rec,
        const schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        uint8_t generator_index
){
    //evaluate the generator index
    if(generator_index != 1 && generator_index != 2) {
        return 0;
    }else if(generator_index == 1){
        if(!scalar_add(&schnorr_seckey_sig->scalar, &schnorr_reduced_shares->scalar, &schnorr_reduced_shares->scalar)){
            return 0;
        }
        //compute seckey for recovery = 3/4 * seckey
        private_secret_scalar temp_scalar;
        temp_scalar.generator_index = generator_index;
        memcpy(temp_scalar.value, prod_3_4_modq, SCALAR_SIZE);
        if(!scalar_mult(&schnorr_seckey_rec->scalar, &schnorr_seckey_sig->scalar, &temp_scalar)){
            return 0;
        }
    }else if (generator_index == 2){
        if(!scalar_negate(&schnorr_seckey_sig->scalar, &schnorr_reduced_shares->scalar)){
            return 0;
        }
        //compute seckey for recovery = -3 * seckey
        private_secret_scalar temp_scalar2;
        if(!scalar_add(&temp_scalar2, &schnorr_seckey_sig->scalar, &schnorr_seckey_sig->scalar)){
            return 0;
        }
        if(!scalar_add(&schnorr_seckey_rec->scalar, &temp_scalar2, &schnorr_seckey_sig->scalar)){
            return 0;
        }
        if(!scalar_negate(&schnorr_seckey_rec->scalar, &schnorr_seckey_rec->scalar)){
            return 0;
        }
    }

    return 1;
}

int schnorr_shamir_shares_reduction(
        schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        const keygen_shamir_secret_share *shamir_shares_arr,
        uint8_t share_num
){
    // check share_num is 3
    if(share_num != 3) {
        return 0;
    }

    // convert the shares into private_secret_scalar
    private_secret_scalar shamir_scalars[3];
    for(int i = 0; i < 3; i++){
        shamir_scalars[i].generator_index = shamir_shares_arr[i].generator_index;
        memcpy(shamir_scalars[i].value, shamir_shares_arr[i].value, SCALAR_SIZE);
    }

    // sum up the shamir shares
    private_secret_scalar tmp_sum;
    if(!scalar_add(&tmp_sum, &shamir_scalars[0], &shamir_scalars[1])){
        return 0;
    }
    // now put the final sum into schnorr_reduced_shares
    if(!scalar_add(&schnorr_reduced_shares->scalar, &tmp_sum, &shamir_scalars[2])){
        return 0;
    }

    return 1;
}

int schnorr_A_3_compute(
        point_extended  *A_3_schnorr_pubkey,
        const point_extended *Y_shares_array
){
    //convert Y_shares_array[0] into gej format
    point_ge temp_point_ge_Y_1;
    point_gej temp_point_gej_Y_1;
    if(!point_ge_parse(&temp_point_ge_Y_1, &Y_shares_array[0])){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_Y_1, &temp_point_ge_Y_1)){
        return 0;
    }

    //compute Y_1 + Y_1
    point_gej temp_point_gej_Y_1_plus_Y_1;
    if(!point_gej_double(&temp_point_gej_Y_1_plus_Y_1, &temp_point_gej_Y_1)){
        return 0;
    }

    // convert Y_shares_array[1] into gej format
    point_ge temp_point_ge_Y_2;
    point_gej temp_point_gej_Y_2;
    if(!point_ge_parse(&temp_point_ge_Y_2, &Y_shares_array[1])){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_Y_2, &temp_point_ge_Y_2)){
        return 0;
    }

    //negate Y_2
    point_gej temp_point_gej_neg_Y_2;
    if(!point_gej_negate(&temp_point_gej_neg_Y_2, &temp_point_gej_Y_2)){
        return 0;
    }

    //compute A_3 = Y_1 + Y_1 - Y_2
    point_gej temp_point_gej_A_3;
    if(!point_gej_add(&temp_point_gej_A_3, &temp_point_gej_Y_1_plus_Y_1, &temp_point_gej_neg_Y_2)){
        return 0;
    }

    // convert A_3 to ge format
    point_ge temp_point_ge_A_3;
    if(!point_gej_to_ge(&temp_point_ge_A_3, &temp_point_gej_A_3)){
        return 0;
    }

    // serialize A_3 into A_3_schnorr_pubkey
    if(!point_ge_serialize(A_3_schnorr_pubkey, &temp_point_ge_A_3)){
        return 0;
    }

    return 1;
}

int schnorr_pubkey_combine(
        schnorr_pubkey *out,
        const point_extended *ins,
        uint8_t n
){
    // check n is 3
    if(n != 3) {
        return 0;
    }

    // convert ins[0] to gej format
    point_ge temp_point_ge_0;
    point_gej temp_point_gej_0;
    if(!point_ge_parse(&temp_point_ge_0, &ins[0])){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_0, &temp_point_ge_0)){
        return 0;
    }

    // convert ins[1] to gej format
    point_ge temp_point_ge_1;
    point_gej temp_point_gej_1;
    if(!point_ge_parse(&temp_point_ge_1, &ins[1])){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_1, &temp_point_ge_1)){
        return 0;
    }

    // convert ins[2] to gej format
    point_ge temp_point_ge_2;
    point_gej temp_point_gej_2;
    if(!point_ge_parse(&temp_point_ge_2, &ins[2])){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_2, &temp_point_ge_2)){
        return 0;
    }

    // compute the sum of the three points
    point_gej temp_sum_gej;
    if(!point_gej_add(&temp_sum_gej, &temp_point_gej_0, &temp_point_gej_1)){
        return 0;
    }
    if(!point_gej_add(&temp_sum_gej, &temp_sum_gej, &temp_point_gej_2)){
        return 0;
    }

    // convert the sum to ge format
    point_ge temp_sum_ge;
    if(!point_gej_to_ge(&temp_sum_ge, &temp_sum_gej)){
        return 0;
    }
    // serialize the sum into out.point
    if(!point_ge_serialize(&out->point, &temp_sum_ge)){
        return 0;
    }

    return 1;
}

int schnorr_prove_knowledge(
        point_extended *u,
        point_extended *h,
        private_secret_scalar *r,
        schnorr_reduced_shamir_shares *schnorr_seckey,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
){
    // generate a random nonce in r
    do {
        csprng_randombytes(r->value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(r->value, SCALAR_SIZE));
    r->generator_index = generator_index;

    // compute u = r * G
    point_gej temp_u_gej;
    if (!point_gej_scalar_mult_base(&temp_u_gej, r)) {
        return 0;
    }
    point_ge temp_u_ge;
    if (!point_gej_to_ge(&temp_u_ge, &temp_u_gej)) {
        return 0;
    }
    if (!point_ge_serialize(u, &temp_u_ge)) {
        return 0;
    }

    //compute h = schnorr_seckey * G
    point_gej temp_h_gej;
    if (!point_gej_scalar_mult_base(&temp_h_gej, &schnorr_seckey->scalar)) {
        return 0;
    }
    point_ge temp_h_ge;
    if (!point_gej_to_ge(&temp_h_ge, &temp_h_gej)) {
        return 0;
    }
    if (!point_ge_serialize(h, &temp_h_ge)) {
        return 0;
    }

    return 1;
}

int schnorr_generate_challenge(
        unsigned char *c,
        const point_extended *u,
        const point_extended *h,
        CSPRNG_STATE_T *csprng_state,
        uint8_t generator_index
){
    //check u and h are not point at infinity
    point_ge temp_point_ge_u;
    point_ge temp_point_ge_h;
    point_gej temp_point_gej_u;
    point_gej temp_point_gej_h;

    if(!point_ge_parse(&temp_point_ge_u, u)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_u, &temp_point_ge_u)){
        return 0;
    }
    if(!point_ge_parse(&temp_point_ge_h, h)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_h, &temp_point_ge_h)){
        return 0;
    }

    if (point_gej_is_infinity(&temp_point_gej_u) || point_gej_is_infinity(&temp_point_gej_h)) {
        return 0;
    }

    //check validity of u and h
    if(!point_gej_is_valid(&temp_point_gej_u) || !point_gej_is_valid(&temp_point_gej_h)){
        return 0;
    }

    //generate random nonce c
    do {
        csprng_randombytes(c, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(c, SCALAR_SIZE));

    return 1;
}

int schnorr_generate_response(
        private_secret_scalar *z,
        const schnorr_reduced_shamir_shares *schnorr_seckey,
        const private_secret_scalar *c,
        const private_secret_scalar *r
){
    // compute z = r + c * s
    private_secret_scalar temp_c_s;
    if (!scalar_mult(&temp_c_s, c, &schnorr_seckey->scalar)) {
        return 0;
    }
    if (!scalar_add(z, r, &temp_c_s)) {
        return 0;
    }

    return 1;
}

int schnorr_verify_proof(
        const point_extended *h,
        const point_extended *u,
        const private_secret_scalar *c,
        const private_secret_scalar *z
){
    //check z!=0
    if(scalar_is_zero(z)){
        return 0;
    }

    // compute z * G
    point_gej temp_zG_gej;
    if (!point_gej_scalar_mult_base(&temp_zG_gej, z)) {
        return 0;
    }

    // compute u + c * h
    point_ge temp_point_ge_u;
    point_ge temp_point_ge_h;
    point_gej temp_point_gej_h;

    if(!point_ge_parse(&temp_point_ge_u, u)){
        return 0;
    }
    if(!point_ge_parse(&temp_point_ge_h, h)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_point_gej_h, &temp_point_ge_h)){
        return 0;
    }
    point_gej temp_c_h_gej;
    if (!point_gej_scalar_mult(&temp_c_h_gej, &temp_point_gej_h, c)) {
        return 0;
    }

    point_gej temp_u_plus_c_h_gej;
    if(!point_gej_add_ge(&temp_u_plus_c_h_gej, &temp_c_h_gej, &temp_point_ge_u)){
        return 0;
    }

    // check if z * G == u + c * h
    if (!point_gej_equal(&temp_zG_gej, &temp_u_plus_c_h_gej)) {
        return 0;
    }

    return 1;
}

int schnorr_sign_phase1(
        private_secret_scalar *sec_scalar,
        point_extended *r_i,
        commitment_packet *commitment_packet,
        uint8_t generator_index,
        CSPRNG_STATE_T *csprng_state
){
    // generate a random nonce in sec_scalar
    do {
        csprng_randombytes(sec_scalar->value, SCALAR_SIZE, csprng_state);
    } while (!rejection_sampling_q(sec_scalar->value, SCALAR_SIZE));
    sec_scalar->generator_index = generator_index;

    // compute r_i = sec_scalar * G
    point_gej temp_r_i_gej;
    if (!point_gej_scalar_mult_base(&temp_r_i_gej, sec_scalar)) {
        return 0;
    }
    point_ge temp_r_i_ge;
    if (!point_gej_to_ge(&temp_r_i_ge, &temp_r_i_gej)) {
        return 0;
    }
    if (!point_ge_serialize(r_i, &temp_r_i_ge)) {
        return 0;
    }

    // fill commitment packet
    if(!commit_point(commitment_packet, r_i, DSC_SIGN_COMMIT_R, csprng_state)){
        return 0;
    }

    return 1;
}

int schnorr_sign_phase2(
        schnorr_hash_challenge *schnorr_signature_chall,
        private_secret_scalar *schnorr_signature_part_resp,
        commitment_packet *commitment_packet,
        const schnorr_seckey *schnorr_seckey,
        const private_secret_scalar *sec_scalar,
        const unsigned char *message,
        uint8_t message_len,
        const point_extended *nonce,
        uint8_t generator_index,
        CSPRNG_STATE_T *csprng_state
){
    // tmp for storing 32 bytes hash output
    unsigned char tmp_hash[HASH_DIGEST_LENGTH];

    // tmp for storing r_x
    unsigned char r_x[SCALAR_SIZE];
    memcpy(r_x, &nonce->value[1], SCALAR_SIZE);

    //generate challenge c = H(r_x || message) with rejection sampling
    uint8_t counter = 0;
    do {
        hash_spec(tmp_hash, r_x, message, message_len, DSC_SIGN_CHALLENGE, counter);
        counter++;
    } while (!rejection_sampling_q(tmp_hash, HASH_DIGEST_LENGTH));

    unsigned char *tmp_chall;

    if(ECDSA_SCHNORR_SIGNATURE_E_SIZE == 16){
        //reduce tmp_hash to 16 bytes by taking the first 16 bytes
        memcpy(schnorr_signature_chall, tmp_hash, ECDSA_SCHNORR_SIGNATURE_E_SIZE);

        // create a tmp_chall to store a 32 byte version of the challenge for scalar multiplication
        tmp_chall = (unsigned char *)malloc(32);
        memset(tmp_chall, 0, 32);
        memcpy(&tmp_chall[16], schnorr_signature_chall, 16);
    }else{
        // signature challenge is 32 bytes, directly use tmp_hash as the challenge
        memcpy(schnorr_signature_chall, tmp_hash, ECDSA_SCHNORR_SIGNATURE_E_SIZE);

        tmp_chall = (unsigned char *)malloc(SCALAR_SIZE);
        memset(tmp_chall, 0, SCALAR_SIZE);
        memcpy(&tmp_chall[SCALAR_SIZE-ECDSA_SCHNORR_SIGNATURE_E_SIZE], schnorr_signature_chall, ECDSA_SCHNORR_SIGNATURE_E_SIZE);
    }

    //compute schnorr_signature_part_resp as sec_scalar - tmp_chall * schnorr_seckey
    private_secret_scalar tmp_chall_scalar;
    tmp_chall_scalar.generator_index = generator_index;
    memcpy(tmp_chall_scalar.value, tmp_chall, SCALAR_SIZE);

    //compute tmp_chall * schnorr_seckey
    private_secret_scalar tmp_chall_s_sk;
    if (!scalar_mult(&tmp_chall_s_sk, &tmp_chall_scalar, &schnorr_seckey->scalar)) {
        return 0;
    }

    //negate tmp_chall_s_sk
    if (!scalar_negate(&tmp_chall_s_sk, &tmp_chall_s_sk)) {
        return 0;
    }

    //compute schnorr_signature_part_resp = sec_scalar + (- tmp_chall * schnorr_seckey)
    if (!scalar_add(schnorr_signature_part_resp, sec_scalar, &tmp_chall_s_sk)) {
        return 0;
    }

    //commit scalar schnorr_signature_part_resp
    if(!commit_scalar(commitment_packet, schnorr_signature_part_resp, DSC_SIGN_COMMIT_S, csprng_state)){
        return 0;
    }

    return 1;
}

int schnorr_signature_combine(
        schnorr_signature *sig,
        private_secret_scalar *partial_resps,
        uint8_t n_partial_resps,
        schnorr_hash_challenge *chall
){
    // check n_partial_resps is 2
    if(n_partial_resps != 2) {
        return 0;
    }

    // sum up the partial responses
    private_secret_scalar tmp_sum;
    if(!scalar_add(&tmp_sum, &partial_resps[0], &partial_resps[1])){
        return 0;
    }

    // put the final sum into sig->s
    memcpy(sig->s, tmp_sum.value, SCALAR_SIZE);

    // put the challenge into sig->e
    memcpy(sig->e, chall, ECDSA_SCHNORR_SIGNATURE_E_SIZE);

    return 1;
}

int schnorrsig_verify(
        const schnorr_signature *sig,
        const unsigned char *msg,
        uint8_t msglen,
        const schnorr_pubkey *pubkey
){
    //compute verify_nonce as sig->s * G + sig->e * pubkey
    point_extended verify_nonce;
    point_gej temp_sG_gej;
    point_gej temp_eP_gej;

    private_secret_scalar s_scalar;
    memcpy(s_scalar.value, sig->s, SCALAR_SIZE);

    private_secret_scalar e_scalar;
    memset(e_scalar.value, 0, SCALAR_SIZE);
    memcpy(&e_scalar.value[SCALAR_SIZE-ECDSA_SCHNORR_SIGNATURE_E_SIZE], sig->e, ECDSA_SCHNORR_SIGNATURE_E_SIZE);

    if (!point_gej_scalar_mult_base(&temp_sG_gej, &s_scalar)) {
        return 0;
    }

    point_ge temp_pubkey_ge;
    point_gej temp_pubkey_gej;
    if(!point_ge_parse(&temp_pubkey_ge, &pubkey->point)){
        return 0;
    }
    if(!point_ge_to_gej(&temp_pubkey_gej, &temp_pubkey_ge)){
        return 0;
    }
    if (!point_gej_scalar_mult(&temp_eP_gej, &temp_pubkey_gej, &e_scalar)) {
        return 0;
    }

    point_gej temp_verify_nonce_gej;
    if(!point_gej_add(&temp_verify_nonce_gej, &temp_sG_gej, &temp_eP_gej)){
        return 0;
    }

    // serialize verify_nonce_gej to verify_nonce
    point_ge temp_verify_nonce_ge;
    if(!point_gej_to_ge(&temp_verify_nonce_ge, &temp_verify_nonce_gej)){
        return 0;
    }
    if(!point_ge_serialize(&verify_nonce, &temp_verify_nonce_ge)){
        return 0;
    }

    //generate challenge c' = H(verify_nonce || msg) with rejection sampling
    unsigned char tmp_hash[HASH_DIGEST_LENGTH];
    uint8_t counter = 0;
    unsigned char r_x [SCALAR_SIZE];
    memcpy(r_x, &verify_nonce.value[1], SCALAR_SIZE);

    do {
        hash_spec(tmp_hash, r_x, msg, msglen, DSC_SIGN_CHALLENGE, counter);
        counter++;
    } while (!rejection_sampling_q(tmp_hash, HASH_DIGEST_LENGTH));

    unsigned char recomputed_chall[ECDSA_SCHNORR_SIGNATURE_E_SIZE];
    memcpy(recomputed_chall, tmp_hash, ECDSA_SCHNORR_SIGNATURE_E_SIZE);

    //printf("Recomputed challenge: ");
    // compare recomputed_chall with sig->e
    if (memcmp(recomputed_chall, sig->e, ECDSA_SCHNORR_SIGNATURE_E_SIZE) != 0) {
        return 0;
    }

    return 1;
}

int schnorr_recovery_pubkey_share_gen(
        private_secret_scalar *a_3_scalar,
        point_extended *A_3_pubkey,
        const keygen_shamir_secret_share *shamir_share_arr
){
    // compute 2 * y_3_1
    private_secret_scalar y_3_1_scalar;
    y_3_1_scalar.generator_index = shamir_share_arr[1].generator_index;
    memcpy(y_3_1_scalar.value, shamir_share_arr[1].value, SCALAR_SIZE);

    if(!scalar_add(a_3_scalar, &y_3_1_scalar, &y_3_1_scalar)){
        return 0;
    }

    //compute - y_3_2
    private_secret_scalar y_3_2_scalar;
    y_3_2_scalar.generator_index = shamir_share_arr[3].generator_index;
    memcpy(y_3_2_scalar.value, shamir_share_arr[3].value, SCALAR_SIZE);

    if(!scalar_negate(&y_3_2_scalar, &y_3_2_scalar)){
        return 0;
    }

    //add 2 * y_3_1 and - y_3_2 to get a_3_scalar
    if(!scalar_add(a_3_scalar, a_3_scalar, &y_3_2_scalar)){
        return 0;
    }

    // compute A_3_pubkey = a_3_scalar * G
    point_gej temp_A_3_gej;
    if (!point_gej_scalar_mult_base(&temp_A_3_gej, a_3_scalar)) {
        return 0;
    }
    point_ge temp_A_3_ge;
    if (!point_gej_to_ge(&temp_A_3_ge, &temp_A_3_gej)) {
        return 0;
    }
    if (!point_ge_serialize(A_3_pubkey, &temp_A_3_ge)) {
        return 0;
    }

    return 1;
}

int schnorr_shamir_shares_reduction_recovery(
        schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        const keygen_shamir_secret_share *shamir_shares_arr,
        uint8_t share_num
){
    if(share_num != 4) {
        return 0;
    }

    private_secret_scalar sum;

    private_secret_scalar shamir_scalars[4];
    for(int i = 0; i < 4; i++){
        shamir_scalars[i].generator_index = shamir_shares_arr[i].generator_index;
        memcpy(shamir_scalars[i].value, shamir_shares_arr[i].value, SCALAR_SIZE);
    }

    // compute sum = y_1_3 + y_2_3 + 2*y_3_2 - y_3_1
    if(!scalar_add(&sum, &shamir_scalars[0], &shamir_scalars[2])){
        return 0;
    }
    if(!scalar_add(&shamir_scalars[3], &shamir_scalars[3], &shamir_scalars[3])){
        return 0;
    }
    if(!scalar_add(&sum, &sum, &shamir_scalars[3])){
        return 0;
    }
    if(!scalar_negate(&shamir_scalars[1], &shamir_scalars[1])){
        return 0;
    }
    if(!scalar_add(&sum, &sum, &shamir_scalars[1])){
        return 0;
    }

    // put the final sum into schnorr_reduced_shares
    memcpy(schnorr_reduced_shares->scalar.value, sum.value, SCALAR_SIZE);
    schnorr_reduced_shares->scalar.generator_index = 3;

    return 1;
}

int schnorr_keygen_generate_recovery_seckey(
        schnorr_seckey *schnorr_seckey_rec,
        const schnorr_reduced_shamir_shares *schnorr_reduced_shares,
        uint8_t generator_index
){
    if(generator_index == 1){
        // schnorr_seckey_recovery = -1/2 * schnorr_reduced_shares
        private_secret_scalar temp_scalar;
        private_secret_scalar half_scalar;
        half_scalar.generator_index = generator_index;
        memcpy(half_scalar.value, &prod_1_2_modq, SCALAR_SIZE);
        if(!scalar_mult(&temp_scalar, &schnorr_reduced_shares->scalar, &half_scalar)){
            return 0;
        }
        if(!scalar_negate(&schnorr_seckey_rec->scalar, &temp_scalar)){
            return 0;
        }
    }else if (generator_index == 2) {
        // schnorr_seckey_recovery = -2 * schnorr_reduced_shares
        if (!scalar_add(&schnorr_seckey_rec->scalar, &schnorr_reduced_shares->scalar,
                        &schnorr_reduced_shares->scalar)) {
            return 0;
        }
        if (!scalar_negate(&schnorr_seckey_rec->scalar, &schnorr_seckey_rec->scalar)) {
            return 0;
        }
    }else {
        return 0;
    }

    schnorr_seckey_rec->scalar.generator_index = 3;
    return 1;
}

int schnorr_verify_commitment(
        const commitment_packet *commitment_packet
){
    if(commitment_packet->decommitment.value_len != SCALAR_SIZE && commitment_packet->decommitment.value_len != POINT_SIZE){
        return 0;
    }
    if(commitment_packet->decommitment.value_len == SCALAR_SIZE) {
        unsigned char m[SCALAR_SIZE + 8];
        unsigned char *m_cursor = m;

        uint64_t value_len_le = SCALAR_SIZE;
        memcpy(m_cursor, &value_len_le, 8);
        m_cursor += 8;
        memcpy(m_cursor, commitment_packet->decommitment.value, SCALAR_SIZE);

        unsigned char hash_digest[HASH_DIGEST_LENGTH];
        uint8_t counter = 1;
        hash(hash_digest, commitment_packet->decommitment.nonce, m, SCALAR_SIZE+8, DSC_SIGN_COMMIT_S, counter);

        if (memcmp(hash_digest, commitment_packet->commitment.data, HASH_DIGEST_LENGTH) != 0) {
            return 0;
        }
    }else if (commitment_packet->decommitment.value_len == POINT_SIZE) {
        // this is a point commitment, we verify by recomputing the commitment hash and comparing
        unsigned char m[SCALAR_SIZE*2 + 16];
        unsigned char *m_cursor = m;

        uint64_t x_len_le = SCALAR_SIZE;
        memcpy(m_cursor, &x_len_le, 8);
        m_cursor += 8;
        memcpy(m_cursor, &commitment_packet->decommitment.value[1], SCALAR_SIZE);
        m_cursor += SCALAR_SIZE;

        uint64_t y_len_le = SCALAR_SIZE;
        memcpy(m_cursor, &y_len_le, 8);
        m_cursor += 8;
        memcpy(m_cursor, &commitment_packet->decommitment.value[1+SCALAR_SIZE], SCALAR_SIZE);

        unsigned char hash_digest_1[HASH_DIGEST_LENGTH]; //using dsc = DSC_KEYGEN_COMMIT
        unsigned char hash_digest_2[HASH_DIGEST_LENGTH]; //using dsc = DSC_SIGN_COMMIT_R
        uint8_t counter = 1;

        hash(hash_digest_1, commitment_packet->decommitment.nonce, m, SCALAR_SIZE*2+16, DSC_KEYGEN_COMMIT, counter);
        hash(hash_digest_2, commitment_packet->decommitment.nonce, m, SCALAR_SIZE*2+16, DSC_SIGN_COMMIT_R, counter);

        if (memcmp(hash_digest_1, commitment_packet->commitment.data, HASH_DIGEST_LENGTH) != 0 &&
            memcmp(hash_digest_2, commitment_packet->commitment.data, HASH_DIGEST_LENGTH) != 0) {
            return 0;
        }
    }

    return 1;
}

int recovery_info_decrypt(
        schnorr_pubkey *pubkey,
        keygen_shamir_secret_share *out_share_arr,
        const signature_recovery_info *recovery_info,
        EVP_PKEY *rsa_privkey
){
    // copy value of A
    memcpy(pubkey, &recovery_info->pubkey, sizeof(schnorr_pubkey));

    // Recovery decrypts
    unsigned char decrypted_y_1_3[RSA_PLAINTEXT_SIZE];
    unsigned char decrypted_y_3_1[RSA_PLAINTEXT_SIZE];
    unsigned char decrypted_y_2_3[RSA_PLAINTEXT_SIZE];
    unsigned char decrypted_y_3_2[RSA_PLAINTEXT_SIZE];

    if(!secp256r1_rsa_decrypt(
            decrypted_y_1_3,
            rsa_privkey,
            recovery_info->recovery_packet_1_3.encrypted_y_i3
    )){
        printf("[SETUP ERRORE] Decrypt di y_1_3 fallito!\n");
    }
    if(!secp256r1_rsa_decrypt(
            decrypted_y_3_1,
            rsa_privkey,
            recovery_info->recovery_packet_1_3.encrypted_y_3i
    )){
        printf("[SETUP ERRORE] Decrypt di y_3_1 fallito!\n");
    }
    if(!secp256r1_rsa_decrypt(
            decrypted_y_2_3,
            rsa_privkey,
            recovery_info->recovery_packet_2_3.encrypted_y_i3
    )){
        printf("[SETUP ERRORE] Decrypt di y_2_3 fallito!\n");
    }
    if(!secp256r1_rsa_decrypt(
            decrypted_y_3_2,
            rsa_privkey,
            recovery_info->recovery_packet_2_3.encrypted_y_3i
    )){
        printf("[SETUP ERRORE] Decrypt di y_3_2 fallito!\n");
    }

    //put the values correctly into the structure
    memcpy(out_share_arr[0].value, decrypted_y_1_3, RSA_PLAINTEXT_SIZE);
    memcpy(out_share_arr[1].value, decrypted_y_3_1, RSA_PLAINTEXT_SIZE);
    memcpy(out_share_arr[2].value, decrypted_y_2_3, RSA_PLAINTEXT_SIZE);
    memcpy(out_share_arr[3].value, decrypted_y_3_2, RSA_PLAINTEXT_SIZE);

    return 1;
}

int collect_random_seed(
        unsigned char *seed
){
    ssize_t res = getrandom(seed, 32, 0);

    if (res < 0 || (size_t)res != 32) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) {
            return 0;
        }
        size_t read_bytes = fread(seed, 1, 32, f);
        fclose(f);
        return (read_bytes == 32);
    }

    return 1;
}

int schnorr_compute_signature_nonce(
        point_extended *R,
        const point_extended *r_i_array,
        uint8_t n_signers
){
    point_ge r_i_tmp;
    point_gej r_i_gej_tmp;
    point_ge r_other_tmp;
    point_gej r_other_gej_tmp;
    point_gej sum_tmp;
    point_ge sum_ge_tmp;


    if(!point_ge_parse(&r_i_tmp, &r_i_array[0])){
        return 0;
    }
    if(!point_ge_to_gej(&r_i_gej_tmp, &r_i_tmp)){
        return 0;
    }

    if(!point_ge_parse(&r_other_tmp, &r_i_array[1])){
        return 0;
    }
    if(!point_ge_to_gej(&r_other_gej_tmp, &r_other_tmp)){
        return 0;
    }

    if(!point_gej_add(&sum_tmp, &r_i_gej_tmp, &r_other_gej_tmp)){
        return 0;
    }

    if(!point_gej_to_ge(&sum_ge_tmp, &sum_tmp)){
        return 0;
    }

    if(!point_ge_serialize(R, &sum_ge_tmp)){
        return 0;
    }
}