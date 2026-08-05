#ifndef CTR_DRBG_BCC_H
#define CTR_DRBG_BCC_H

#include "ctr_drbg.h"
#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus ctr_drbg_bcc(
    const uint8_t key[CTR_DRBG_KEY_BYTES],
    const uint8_t *data,
    size_t data_len,
    uint8_t output[CTR_DRBG_BLOCK_BYTES]);

#endif