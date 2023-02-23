/*
    Revenge of LLLattice
    pbctf 2023

    Copyright (c) 2023 Team CyberSecurityAustria
    Authors: Johannes Berndorfer (@berndoJ) & Jonas Konrad (@austriangam3r)

    TEA decryption routine for decrypting the flag.enc file.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

const unsigned int KEYS[4] = {0x63636f62, 0x7a206968, 0x6f722061, 0x00216b63};

/* TEA decryption routine from Wikipedia, see https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm. */
void decrypt(unsigned int v[2], const unsigned int k[4])
{
    unsigned int v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;   /* set up; sum is 32*delta */
    unsigned int delta = 0x9E3779B9;                          /* a key schedule constant */
    unsigned int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];  /* cache key */
    for(i = 0; i<32; i++) {                                   /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                         /* end cycle */
    }
    v[0] = v0; v[1] = v1;
}

void main(int argc, char *argv[])
{
    FILE *fp;
    unsigned char buf[8];
    char out_string[256] = {0};
    unsigned int v[2];
    unsigned int offset = 0;

    if (argc < 2)
    {
        fprintf(stderr, "Error: Please specify flag file.\n");
        exit(1);
    }

    fp = fopen(argv[1], "rb");

    if (!fp)
    {
        fprintf(stderr, "Error: Could not open flag file. Aborting.\n");
        exit(1);
    }

    while (fread(buf, 1, 8, fp) == 8 && offset + 8 < 256)
    {
        /* This hack only works on little endian - but who has big endian
           anyways nowadays... */
        v[0] = *(unsigned int *)(&buf[0]);
        v[1] = *(unsigned int *)(&buf[4]);

        decrypt(v, KEYS);

        memcpy(out_string + offset, v, 8);
        offset += 8;
    }

    puts(out_string);

    fclose(fp);
}