#ifndef BLOCK_CIPHER_DF_H
#define BLOCK_CIPHER_DF_H

#include "ctr_drbg.h"
#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus block_cipher_df(
    const uint8_t *input,
    size_t input_len,
    uint8_t output[CTR_DRBG_SEED_BYTES]);

#endif