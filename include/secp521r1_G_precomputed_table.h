//
// Created by PC on 31/05/2026.
//

#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL 128
#endif

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_G_PRECOMPUTED_TABLE_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_G_PRECOMPUTED_TABLE_H

#include "EC_arithmetics.h"

#if SECURITY_LEVEL == 256

#ifndef WINDOW_SIZE
#define WINDOW_SIZE 4  // default
#endif

#if (WINDOW_SIZE != 2) && (WINDOW_SIZE != 4) && (WINDOW_SIZE != 8)
#error "WINDOW_SIZE value not valid! Supported: 2 (Low-Memory), 4 (Balanced), 8 (High-Performance)."
#endif

#define PRECOMPUTED_G_SIZE ((1 << WINDOW_SIZE) - 1)

extern const point_ge PRECOMPUTED_G[PRECOMPUTED_G_SIZE];

#endif
#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SECP521R1_G_PRECOMPUTED_TABLE_H
