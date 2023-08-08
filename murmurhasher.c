#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "murmurhasher.h"

static unsigned int hash32(unsigned char *data, int length, int seed);
static int rotateLeft(unsigned int k, int d);


long hash(char *url)
{
    return 0xFFFFFFFFL & hash32((unsigned char *)url, strlen(url), DEFAULT_SEED);
}

static unsigned int hash32(unsigned char *data, int length, int seed)
{
    int i;
    unsigned int hash = seed; // 改成无符号数
    const int nblocks = length >> 2;

    // body
    for (i = 0; i < nblocks; i++) {
        int i_4 = i << 2;
        unsigned int k = (data[i_4] & 0xff) | ((data[i_4 + 1] & 0xff) << 8) |
                ((data[i_4 + 2] & 0xff) << 16) | ((data[i_4 + 3] & 0xff) << 24); // 改成无符号数
        // mix functions
        k *= C1_32;
        k = rotateLeft(k, R1_32); //(k << R1_32) | (k >>> (32 - R1_32));
        k *= C2_32;
        hash ^= k;
        hash = rotateLeft(hash, R2_32); // (hash << R2_32) | (hash >>> (32 - R2_32));
        hash = hash * M_32 + N_32;
    }

    // tail
    int idx = nblocks << 2;
    int k1 = 0;
    switch (length - idx)
    {
    case 3:
        k1 ^= data[idx + 2] << 16;
    case 2:
        k1 ^= data[idx + 1] << 8;
    case 1:
        k1 ^= data[idx];

        // mix functions
        k1 *= C1_32;
        k1 = rotateLeft(k1, R1_32);
        k1 *= C2_32;
        hash ^= k1;
    }

    // finalization
    hash ^= length;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}

static int rotateLeft(unsigned int k, int d) {
    return (k << d) | ( k >> (32 - d));
}