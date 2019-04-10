#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define DATA_LENGTH     2048
#define PMT_SIZE        4
#define TBL_SIZE        16
#define HEAD_SIZE       32
#define DGST_SIZE       32
#define TARG_SIZE       16
#define DATASET_SIZE    4194304


struct search_result
{
    bool solution_found = false;
    uint64_t nonce = 0;

    uint8_t final_hash[32];
    uint8_t mix_hash[32];
};


void fchainhash(uint64_t dataset[], uint8_t mining_hash[], uint64_t nonce, uint8_t digs[]);
//void compute(uint64_t nonce_start);

