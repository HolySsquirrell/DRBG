#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "status.h"

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

DRBGStatus crypto_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[SHA256_DIGEST_SIZE]);

#endif