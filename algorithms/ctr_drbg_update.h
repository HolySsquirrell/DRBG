#ifndef CTR_DRBG_UPDATE_H
#define CTR_DRBG_UPDATE_H

#include "ctr_drbg.h"
#include "status.h"

#include <stdint.h>

DRBGStatus ctr_drbg_update(
    uint8_t key[CTR_DRBG_KEY_BYTES],
    uint8_t v[CTR_DRBG_BLOCK_BYTES],
    const uint8_t provided_data[CTR_DRBG_SEED_BYTES]);

#endif