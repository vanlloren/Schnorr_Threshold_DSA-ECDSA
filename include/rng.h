//
// Created by PC on 23/04/2026.
//

/***********************************************************************
 * Copyright (c) 2025 CROSS Project Contributors
 *
 * Distributed under the terms of the public domain.
 *
 * This code is based on the SHAKE-based RNG from the CROSS project,
 * originally implemented by:
 *   - Alessandro Barenghi
 *   - Marco Gianvecchio
 *   - Patrick Karl
 *   - Gerardo Pelosi
 *   - Jonas Schupp
 *
 * Modifications were made for use in the Threshold Schnorr Signature
 * with Offline Recovery Party.
 ***********************************************************************/

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_RNG_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_RNG_H

#include "sha3.h"

/* ========================================================================
 * Nonce Generation
 * ======================================================================== */

/************************* CSPRNG ********************************/

#define CSPRNG_STATE_T SHAKE_STATE_STRUCT
/* initializes a CSPRNG, given the seed and a state pointer */
static inline
void csprng_initialize(CSPRNG_STATE_T * const csprng_state,
                       const unsigned char * const seed,
                       const uint32_t seed_len_bytes,
                       const uint16_t dsc) {
    xof_shake_init(csprng_state);
    xof_shake_update(csprng_state,seed,seed_len_bytes);
    uint8_t dsc_ordered[2];
    dsc_ordered[0] = dsc & 0xff;
    dsc_ordered[1] = (dsc >> 8) & 0xff;
    xof_shake_update(csprng_state,dsc_ordered,2);
    xof_shake_final(csprng_state);
} /* end initialize_csprng */

/* extracts xlen bytes from the CSPRNG, given the state */
static inline
void csprng_randombytes(unsigned char * const x,
                        unsigned long long xlen,
                        CSPRNG_STATE_T * const csprng_state){
    xof_shake_extract(csprng_state,x,xlen);
}

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_RNG_H