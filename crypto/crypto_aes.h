#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "status.h"

#include <stdint.h>

#define AES256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

DRBGStatus crypto_aes256_encrypt_block(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t input[AES_BLOCK_SIZE],
    uint8_t output[AES_BLOCK_SIZE]);

#endif