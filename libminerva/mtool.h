#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


namespace eturetools {

#define OFF_SKIP_LEN  32768 	     //32768  8230
#define OFF_CYCLE_LEN  8192	    	 //8192  2080
#define SKIP_CYCLE_LEN 2048     	//2048 520

class sha256  {
public:
    static void sha3_256(unsigned char *d, unsigned int s, const unsigned char *m,
	        unsigned int l);

    static unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len);
    static unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
    static unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);

    static unsigned int mod (int a, int b);

    static void keccakp_iota (uint64_t *s, unsigned int nround);
    static void keccakp_chi (uint64_t *s);
    static void keccakp_pi (uint64_t *s);
    static void keccakp_rho (uint64_t *s);
    static void keccakp_theta (uint64_t *s);
    static void keccakp (void *a);
};

class etrue_ds{
public: 
    static uint64_t* updateLookupTBL(uint8_t seeds[OFF_CYCLE_LEN+SKIP_CYCLE_LEN][16],uint64_t *plookupTbl,int plen);
    static uint64_t* updateTBL(int offset[OFF_SKIP_LEN], int skip[OFF_SKIP_LEN], uint64_t *plookupTbl, int plen);
    static bool sha3_256_hash(uint8_t *dest, int dlen, uint8_t *data, int len);
    static bool dataset_hash(uint8_t hash[32], uint64_t *data,int len);
    static int genLookupTable(uint64_t *plookup,int plen, uint32_t *ptable,int tlen);
    static void truehashTableInit(uint64_t *tableLookup,int tlen);
};

}