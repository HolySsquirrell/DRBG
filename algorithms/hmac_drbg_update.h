#ifndef HMAC_DRBG_UPDATE_H
#define HMAC_DRBG_UPDATE_H

#include "hmac_drbg.h"
#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus hmac_drbg_update(
    uint8_t K[HMAC_DRBG_OUTLEN_BYTES],
    uint8_t V[HMAC_DRBG_OUTLEN_BYTES],
    const uint8_t *provided_data,
    size_t provided_data_len);

#endif 