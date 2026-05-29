//
// Created by PC on 23/04/2026.
//

/***********************************************************************
* Copyright (c) 2025 CROSS Project Contributors
        *
        * Distributed under the terms of the public domain.
*
* Implementation of LibKeccak SHAKE wrappers from the CROSS project,
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

//

#ifndef SCHNORR_THRESHOLD_DSA_ECDSA_SHA3_H
#define SCHNORR_THRESHOLD_DSA_ECDSA_SHA3_H

#include <libkeccak.a.headers/KeccakHash.h>

/* LibKeccak SHAKE Wrappers */

#define SHAKE_STATE_STRUCT Keccak_HashInstance
typedef SHAKE_STATE_STRUCT CSPRNG_STATE_T;

static inline
void xof_shake_init(SHAKE_STATE_STRUCT *state)
{
    /* will result in a zero-length output for Keccak_HashFinal */
    Keccak_HashInitialize_SHAKE256(state);
}

static inline
void xof_shake_update(SHAKE_STATE_STRUCT *state,
                      const unsigned char *input,
                      unsigned int inputByteLen)
{
    Keccak_HashUpdate(state,
                      (const BitSequence *) input,
                      (BitLength) inputByteLen*8 );
}

static inline
void xof_shake_final(SHAKE_STATE_STRUCT *state)
{
    Keccak_HashFinal(state, NULL);
}

static inline
void xof_shake_extract(SHAKE_STATE_STRUCT *state,
                       unsigned char *output,
                       unsigned int outputByteLen)
{
    Keccak_HashSqueeze(state,
                       (BitSequence *) output,
                       (BitLength) outputByteLen*8 );
}

#endif //SCHNORR_THRESHOLD_DSA_ECDSA_SHA3_H