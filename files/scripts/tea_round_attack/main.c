/*
    Revenge of LLLattice
    pbctf 2023

    Copyright (c) 2023 Team CyberSecurityAustria
    Authors: Johannes Berndorfer (@berndoJ) & Jonas Konrad (@austriangam3r)

    This is just boilerplate code for the TEA round attack which can be found
    within tea_round_attack.c.
*/

#include "tea_round_attack.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    FILE *fp;
    unsigned int line_count = 0, i, key_cnt;
    struct tea_round_sample_s *sample_buf;
    TEA_U32_t v0_plain, v0_cipher, v1_plain, v1_cipher;
    struct tea_key_s key_candidates[8] = {0};

    if (argc < 2)
    {
        fprintf(stderr, "Error: Please specify sample file.\n");
        return 1;
    }

    /* Open input file. */
    fp = fopen(argv[1], "r");

    if (!fp)
    {
        fprintf(stderr, "Error: Could not open file %s.\n", argv[1]);
        return 1;
    }

    /* Count number of lines for buf */
    while(!feof(fp))
    {
        if (fgetc(fp) == '\n')
        {
            line_count++;
        }
    }

    printf("File contains %u samples.\n", line_count);

    /* Return to start of file */
    fseek(fp, 0, SEEK_SET);

    /* Alloc buffer */
    sample_buf = calloc(line_count + 2, sizeof(struct tea_round_sample_s));
    if (!sample_buf)
    {
        fprintf(stderr, "Error: Out of memory!\n");
        fclose(fp);
        return 1;
    }

    printf("Reading file...\n");

    /* Read in file */
    for (i = 0; i < line_count; i++)
    {
        if (fscanf(fp, "%u %u %u %u\n", &v0_plain, &v1_plain, &v0_cipher, &v1_cipher) == EOF)
        {
            break;
        }

        sample_buf[i].v0_plain = v0_plain;
        sample_buf[i].v1_plain = v1_plain;
        sample_buf[i].v0_cipher = v0_cipher;
        sample_buf[i].v1_cipher = v1_cipher;
    }

    printf("Read %u samples.\nNow bruteforcing... This may take a minute.\n", i);

    /* Attack. */
    key_cnt = tea_round_attack(sample_buf, i, key_candidates, 8, TEA_DEFAULT_DELTA);

    printf("Found %d key pairs.\n", key_cnt);
    for (i = 0; i < key_cnt; i++)
    {
        printf("[%d] K0=0x%08x K1=0x%08x K2=0x%08x K3=0x%08x\n", 
            i, key_candidates[i].k0, key_candidates[i].k1,
            key_candidates[i].k2, key_candidates[i].k3);
    }

    free(sample_buf);
    fclose(fp);

    return 0;
}