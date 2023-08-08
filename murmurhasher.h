#ifndef __DECODER_WORKER_H__
#define __DECODER_WORKER_H__

#define C1_32 0xcc9e2d51
#define C2_32 0x1b873593
#define R1_32 15
#define R2_32 13
#define M_32 5
#define N_32 0xe6546b64
#define DEFAULT_SEED 0

long hash(char* url);

#endif