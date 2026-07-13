#ifndef HASHGEN_H
#define HASHGEN_H

#include "hash_drbg.h"
#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus hashgen(
    const uint8_t V[HASH_DRBG_SEEDLEN_BYTES],
    uint8_t *output,
    size_t output_length);

#endif 