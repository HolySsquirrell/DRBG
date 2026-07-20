#ifndef HMAC_DRBG_H
#define HMAC_DRBG_H

#include "drbg.h"

#include <stddef.h>
#include <stdint.h>

#define HMAC_DRBG_SECURITY_STRENGTH_BITS 256U

#define HMAC_DRBG_ENTROPY_BYTES 32U
#define HMAC_DRBG_NONCE_BYTES 16U

#define HMAC_DRBG_OUTLEN_BYTES 32U

#define HMAC_DRBG_MAX_BYTES_PER_REQUEST \
    ((size_t)1U << 16)

#define HMAC_DRBG_RESEED_INTERVAL \
    (UINT64_C(1) << 48)

typedef struct
{
    uint8_t K[HMAC_DRBG_OUTLEN_BYTES];
    uint8_t V[HMAC_DRBG_OUTLEN_BYTES];

    uint64_t reseed_counter;
} HMACDRBGContext;

extern const DRBG HMACDRBG;

#endif