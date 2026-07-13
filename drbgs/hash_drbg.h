#ifndef HASH_DRBG_H
#define HASH_DRBG_H

#include "drbg.h"

#include <stdint.h>
#include <stddef.h>

#define HASH_DRBG_SEEDLEN_BITS            440
#define HASH_DRBG_SEEDLEN_BYTES           55
#define HASH_DRBG_ENTROPY_BYTES           32
#define HASH_DRBG_NONCE_BYTES             16
#define HASH_DRBG_SECURITY_STRENGTH_BITS  256

#define HASH_DRBG_MAX_BYTES_PER_REQUEST \
    ((size_t)1U << 16)

#define HASH_DRBG_RESEED_INTERVAL \
    (UINT64_C(1) << 48)


typedef struct
{
    uint8_t V[HASH_DRBG_SEEDLEN_BYTES];

    uint8_t C[HASH_DRBG_SEEDLEN_BYTES];

    uint64_t reseed_counter;

} HashDRBGContext;

extern const DRBG HashDRBG;

#endif