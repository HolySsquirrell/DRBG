#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#include "drbg.h"

#include <stddef.h>
#include <stdint.h>

#define CTR_DRBG_SECURITY_STRENGTH_BITS 256U

#define CTR_DRBG_KEY_BYTES 32U
#define CTR_DRBG_BLOCK_BYTES 16U

#define CTR_DRBG_SEED_BYTES \
    (CTR_DRBG_KEY_BYTES + CTR_DRBG_BLOCK_BYTES)

#define CTR_DRBG_ENTROPY_BYTES 32U
#define CTR_DRBG_NONCE_BYTES 16U

#define CTR_DRBG_MAX_BYTES_PER_REQUEST \
    ((size_t)1U << 16)

#define CTR_DRBG_RESEED_INTERVAL \
    (UINT64_C(1) << 48)

_Static_assert(
    CTR_DRBG_KEY_BYTES == 32U,
    "AES-256 key must contain 32 bytes");

_Static_assert(
    CTR_DRBG_BLOCK_BYTES == 16U,
    "AES block must contain 16 bytes");

_Static_assert(
    CTR_DRBG_SEED_BYTES == 48U,
    "AES-256 CTR_DRBG seed must contain 48 bytes");

typedef struct
{
    uint8_t key[CTR_DRBG_KEY_BYTES];
    uint8_t v[CTR_DRBG_BLOCK_BYTES];

    uint64_t reseed_counter;
} CTRDRBGContext;

extern const DRBG CTRDRBG;

#endif