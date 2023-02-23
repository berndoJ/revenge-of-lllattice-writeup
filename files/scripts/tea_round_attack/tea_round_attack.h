/*******************************************************************************
* tea_round_attack.h
* ==================
*
*   This file implements a TEA (Tiny Encryption Algorithm) single-round
*   bruteforce algorithm.
*
*   In essence, TEA can easily be broken (by bruteforcing two 32 bit keys) by
*   obtaining the block data for two consecutive rounds. It is also possible
*   to only extract the first two or last two rounds if the plaintext or
*   ciphertext is already known, so only one round has to be leaked.
*
*   In it's core, each round of TEA applies the following operations:
*       v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
*       v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
*   v0 and v1 are the round data, k0-k3 are the keys and sum is a constant that
*   can be derived from the key schedule constant, which is 0x9E3779B9 for
*   default implementations.
*
*   This algorithm just bruteforces two keys and derives the other two from
*   the equations (2 eq's with 4 variables) and returns a set of possible key
*   pairs. The prediction accuracy rises with more samples, but 16 should
*   usually suffice.
*
*   Date        Rev.No. Author      Description
*   ----------------------------------------------------------------------------
*   20.02.2022  v0.1    konrad      Implemented bruteforce routine for k0/k1. 
*   23.02.2022  v0.1    berndorfer  Extended bruteforce routines, added checks
*                                   and implemented key-candidates (instead of
*                                   just returning a single key candidate.)
*   ----------------------------------------------------------------------------
*
*   Copyright (c) 2023 Johannes Berndorfer / Jonas Konrad
*
*******************************************************************************/

#ifndef __TEA_ROUND_ATTACK_H
#define __TEA_ROUND_ATTACK_H

/* Internal 32bit unsigned int for TEA operations. This may be changed based
   on the target platform. */
typedef unsigned int TEA_U32_t;

#define TEA_U32_MAX         ((TEA_U32_t) 0xFFFFFFFF)
#define TEA_DEFAULT_DELTA   ((TEA_U32_t) 0x9E3779B9)

struct tea_round_sample_s
{
    TEA_U32_t v0_plain;
    TEA_U32_t v1_plain;
    TEA_U32_t v0_cipher;
    TEA_U32_t v1_cipher;
};

struct tea_key_s
{
    TEA_U32_t k0, k1, k2, k3;
};

/**
* Performs a round-based attack on TEA.
*
* @param samples        Buffer of samples supplied to the algorithm. At least 2
*                       samples required.
* @param sample_count   Number of samples within the sample buffer.
* @param keys_out       Output buffer for the key candidates found by the algo.
* @param keys_out_size  Sizer of the output buffer for key candidates.
* @param sum            The round's sum/delta value. For round n, this is
*                       (n+1)*delta.
*/
unsigned int tea_round_attack(
    const struct tea_round_sample_s *samples,
    unsigned int sample_count,
    struct tea_key_s *keys_out,
    unsigned int keys_out_size,
    TEA_U32_t sum
);

#endif // ifndef __TEA_ROUND_ATTACK_H