//
// Created by PC on 23/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_DSC_VALUES_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_DSC_VALUES_H

/** Values for domain separation in the hashing of messages and nonces
 * in the key generation and signing phases of the protocol.
 */

#define DSC_KEYGEN_NONCE              0x0001
#define DSC_KEYGEN_COMMIT_NONCE       0x0002
#define DSC_KEYGEN_COMMIT             0x0003
#define DSC_NIZKP_NONCE               0x0011
#define DSC_NIZKP_HASH                0x0012
#define DSC_ZKP_NONCE                 0x0021
#define DSC_SIGN_NONCE                0x0101
#define DSC_SIGN_COMMIT_R_NONCE       0x0102
#define DSC_SIGN_COMMIT_R             0x0103
#define DSC_SIGN_COMMIT_S_NONCE       0x0201
#define DSC_SIGN_COMMIT_S             0x0202
#define DSC_SIGN_CHALLENGE            0x0301

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_DSC_VALUES_H