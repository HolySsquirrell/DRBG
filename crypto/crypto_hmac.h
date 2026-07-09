#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include "status.h"

#include <stddef.h>
#include <stdint.h>

#define HMAC_SHA256_DIGEST_SIZE 32

DRBGStatus crypto_hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t output[HMAC_SHA256_DIGEST_SIZE]);

#endif