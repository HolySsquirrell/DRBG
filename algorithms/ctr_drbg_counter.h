#ifndef CTR_DRBG_COUNTER_H
#define CTR_DRBG_COUNTER_H

#include "ctr_drbg.h"

#include <stdint.h>

void ctr_drbg_increment(
    uint8_t counter[CTR_DRBG_BLOCK_BYTES]);

#endif