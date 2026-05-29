//
// Created by PC on 22/04/2026.
//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H

#include "schnorr.h"


/* Curve parameters */
extern const unsigned char p[SCALAR_SIZE];   // prime field modulus
extern const unsigned char a[SCALAR_SIZE];   // curve coefficient a
extern const unsigned char b[SCALAR_SIZE];
extern const unsigned char G[POINT_SIZE]; // generator point in uncompressed form
extern const unsigned char q[SCALAR_SIZE];     // order of the curve
extern const unsigned int h;

/* Other constants */
extern const unsigned char p_minus_one[SCALAR_SIZE];
extern const unsigned char zero[SCALAR_SIZE];
extern const unsigned char one[SCALAR_SIZE];
extern const unsigned char q_minus_one[SCALAR_SIZE];
extern const unsigned char prod_3_4_modq[SCALAR_SIZE];
extern const unsigned char prod_1_2_modq[SCALAR_SIZE];

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP256R1_CURVEPARAMS_H
