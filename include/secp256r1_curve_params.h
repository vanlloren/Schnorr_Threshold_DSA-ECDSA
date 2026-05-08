//
// Created by PC on 22/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H

/* Curve paramters */
extern const unsigned char secp256r1_p[32];
extern const unsigned char secp256r1_a[32];
extern const unsigned char secp256r1_b[32];
extern const unsigned char secp256r1_G[65];
extern const unsigned char secp256r1_q[32];     // order of the curve
extern const unsigned int secp256r1_h;

/* Other constants */
extern const unsigned char secp256r1_p_minus_one[32];
extern const unsigned char secp256r1_zero[32];
extern const unsigned char secp256r1_one[32];

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H
