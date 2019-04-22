#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define DATALENGTH     2048
#define PMTSIZE        4
#define TBLSIZE        16

#define HEAD_SIZE       32
#define DGST_SIZE       32
#define TARG_SIZE       16

#define DATASET_SIZE    4194304

void fchainhash(uint64_t dataset[], uint8_t mining_hash[], uint64_t nonce, uint8_t digs[]);
void table_init(uint64_t *plookup);
//void compute(uint64_t nonce_start);

