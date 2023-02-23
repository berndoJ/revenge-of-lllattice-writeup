/*******************************************************************************
* tea_round_attack.c
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
*   standard implementations.
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

#include "tea_round_attack.h"

#define TEA_KEY_CANDIDATES_BUF_SIZE     20

/* ==== PRIVATE FUNCTION PROTOTYPES ========================================= */

/* Checks for all given samples if the specified k0/k1 key-pair is valid. */
static int _tea_check_k0_k1(const struct tea_round_sample_s *samples, unsigned int sample_count,
    TEA_U32_t k0, TEA_U32_t k1, TEA_U32_t delta);

/* Checks for all given samples if the specified k2/k3 key-pair is valid. */
static int _tea_check_k2_k3(const struct tea_round_sample_s *samples, unsigned int sample_count,
    TEA_U32_t k2, TEA_U32_t k3, TEA_U32_t delta);

/* ========================================================================== */

unsigned int tea_round_attack( const struct tea_round_sample_s *samples,
    unsigned int sample_count, struct tea_key_s *keys_out,
    unsigned int keys_out_size, TEA_U32_t delta )
{
    unsigned int i, j, kc_i;
    TEA_U32_t k0, k1_s1, k1_s2;
    TEA_U32_t k2, k3_s1, k3_s2;
    struct tea_round_sample_s s1, s2;

    unsigned int k0_k1_i = 0;
    TEA_U32_t k0_k1_candidates[TEA_KEY_CANDIDATES_BUF_SIZE][2] = {0};

    unsigned int k2_k3_i = 0;
    TEA_U32_t k2_k3_candidates[TEA_KEY_CANDIDATES_BUF_SIZE][2] = {0};

    /* Sanity check */
    if (!samples || sample_count < 2 || !keys_out)
    {
        return 0;
    }

    s1 = samples[0];
    s2 = samples[1];

    /* Bruteforce all possible k0 values. */
    for (k0 = 0; ; k0++)
    {
        k1_s1 = ((s1.v0_cipher - s1.v0_plain) ^ ((s1.v1_plain << 4) + k0) ^ (s1.v1_plain + delta)) - (s1.v1_plain >> 5);
        k1_s2 = ((s2.v0_cipher - s2.v0_plain) ^ ((s2.v1_plain << 4) + k0) ^ (s2.v1_plain + delta)) - (s2.v1_plain >> 5);

        if (k1_s1 == k1_s2)
        {
            /* Check if this key holds for all samples. */
            if (!_tea_check_k0_k1(samples, sample_count, k0, k1_s1, delta))
            {
                /* Key rejected */
                continue;
            }

            /* Key accepted. Add to candidates */
            if (k0_k1_i < TEA_KEY_CANDIDATES_BUF_SIZE)
            {
                k0_k1_candidates[k0_k1_i][0] = k0;
                k0_k1_candidates[k0_k1_i][1] = k1_s1;

                k0_k1_i++;
            }
            else
            {
                break;
            }
        }

        if (k0 == TEA_U32_MAX) break; /* Loop condition */
    }

    /* Bruteforce all possible k2 values. */
    for (k2 = 0; ; k2++)
    {
        k3_s1 = ((s1.v1_cipher - s1.v1_plain) ^ ((s1.v0_cipher << 4) + k2) ^ (s1.v0_cipher + delta)) - (s1.v0_cipher >> 5);
        k3_s2 = ((s2.v1_cipher - s2.v1_plain) ^ ((s2.v0_cipher << 4) + k2) ^ (s2.v0_cipher + delta)) - (s2.v0_cipher >> 5);

        if (k3_s1 == k3_s2)
        {
            /* Check if this key holds for all samples. */
            if (!_tea_check_k2_k3(samples, sample_count, k2, k3_s1, delta))
            {
                /* Key rejected. */
                continue;
            }

            /* Key accepted. Add to candidates */
            if (k2_k3_i < TEA_KEY_CANDIDATES_BUF_SIZE)
            {
                k2_k3_candidates[k2_k3_i][0] = k2;
                k2_k3_candidates[k2_k3_i][1] = k3_s1;

                k2_k3_i++;
            }
            else
            {
                break;
            }
        }

        if (k2 == TEA_U32_MAX) break; /* Loop condition */
    }

    /* Consolidate k0/k1 and k2/k3 candidates in a candidate list. */
    kc_i = 0;
    for (i = 0; i < k0_k1_i; i++)
    {
        for (j = 0; j < k2_k3_i; j++)
        {
            if (kc_i >= keys_out_size)
            {
                break;
            }

            keys_out[kc_i].k0 = k0_k1_candidates[i][0];
            keys_out[kc_i].k1 = k0_k1_candidates[i][1];
            keys_out[kc_i].k2 = k2_k3_candidates[j][0];
            keys_out[kc_i].k3 = k2_k3_candidates[j][1];

            kc_i++;
        }
    }

    return kc_i;    
}

/* ========================================================================== */

static int _tea_check_k0_k1(const struct tea_round_sample_s *samples, unsigned int sample_count,
    TEA_U32_t k0, TEA_U32_t k1, TEA_U32_t delta)
{
    unsigned int i;
    TEA_U32_t v0_cipher_calc;
    struct tea_round_sample_s s;

    for (i = 0; i < sample_count; i++)
    {
        s = samples[i];
        v0_cipher_calc = s.v0_plain + (((s.v1_plain << 4) + k0) ^ (s.v1_plain + delta) ^ ((s.v1_plain >> 5) + k1));

        if (s.v0_cipher != v0_cipher_calc)
        {
            /* Key rejected. */
            return 0;
        }
    }

    return 1;
}

static int _tea_check_k2_k3(const struct tea_round_sample_s *samples, unsigned int sample_count,
    TEA_U32_t k2, TEA_U32_t k3, TEA_U32_t delta)
{
    unsigned int i;
    TEA_U32_t v1_cipher_calc;
    struct tea_round_sample_s s;

    for (i = 0; i < sample_count; i++)
    {
        s = samples[i];
        v1_cipher_calc = s.v1_plain + (((s.v0_cipher << 4) + k2) ^ (s.v0_cipher + delta) ^ ((s.v0_cipher >> 5) + k3));

        if (s.v1_cipher != v1_cipher_calc)
        {
            /* Key rejected. */
            return 0;
        }
    }

    return 1;
}