//
// Created by PC on 31/05/2026.
//
#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL 128
#endif

#if SECURITY_LEVEL == 256
#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_CURVE_PARAMS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_CURVE_PARAMS_H

#include "schnorr.h"

/* Curve parameters */
extern const unsigned char p[SCALAR_SIZE];   // prime field modulus
extern const unsigned char G[POINT_SIZE]; // generator point in uncompressed form
extern const unsigned char q[SCALAR_SIZE];     // order of the curve
extern const unsigned int h;

/* Other constants */
extern const unsigned char zero[SCALAR_SIZE];
extern const unsigned char one[SCALAR_SIZE];
extern const unsigned char q_minus_one[SCALAR_SIZE];
extern const unsigned char prod_3_4_modq[SCALAR_SIZE];
extern const unsigned char prod_1_2_modq[SCALAR_SIZE];

#endif
#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_CURVE_PARAMS_H
