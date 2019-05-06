#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "hash.h"


namespace eturetools {

#define OFF_SKIP_LEN  32768 	     //32768  8230
#define OFF_CYCLE_LEN  8192	    	 //8192  2080
#define SKIP_CYCLE_LEN 2048     	//2048 520


class etrue_ds{
public: 
    static uint64_t* updateLookupTBL(uint8_t seeds[OFF_CYCLE_LEN+SKIP_CYCLE_LEN][16],uint64_t *plookupTbl,int plen);
    static uint64_t* updateTBL(int offset[OFF_SKIP_LEN], int skip[OFF_SKIP_LEN], uint64_t *plookupTbl, int plen);
    static bool dataset_hash(uint8_t hash[32], uint64_t *data,int len);
    static int genLookupTable(uint64_t *plookup,int plen, uint32_t *ptable,int tlen);
    static void truehashTableInit(uint64_t *tableLookup,int tlen);
};

class etrue_minerva_cpu {
public:
    static void truehashFull(uint64_t *dataset,int dlen,uint8_t hash[DGST_SIZE], uint64_t nonce,uint8_t digset[DGST_SIZE]);
private:
    static int byteReverse(uint8_t *sha512_out,int len);
    static int xor64(uint64_t val);
    static uint32_t muliple(uint64_t* input,int inputlen,uint64_t* prow,int prowlen);
    static int MatMuliple(uint64_t* input,int inputlen,uint64_t* output,int outlen,uint64_t* pmat,int pmatlen);
    static int shift2048(uint64_t *in, int inlen, int sf);
    static int scramble(uint64_t *permute_in,int inlen, uint64_t *plookup, int plen);
    static void fchainmining(uint64_t *plookup,int plen, uint8_t header[DGST_SIZE],uint64_t nonce,uint8_t digset[DGST_SIZE]);
};

}