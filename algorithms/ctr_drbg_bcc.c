#include "ctr_drbg_bcc.h"

#include "crypto_aes.h"
#include "utils.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static DRBGStatus encrypt_block(
    const uint8_t key[CTR_DRBG_KEY_BYTES],
    const uint8_t input[CTR_DRBG_BLOCK_BYTES],
    uint8_t output[CTR_DRBG_BLOCK_BYTES])
{
    return crypto_aes256_encrypt_block(
        key,
        input,
        output);
}

DRBGStatus ctr_drbg_bcc(
    const uint8_t key[CTR_DRBG_KEY_BYTES],
    const uint8_t *data,
    size_t data_len,
    uint8_t output[CTR_DRBG_BLOCK_BYTES])
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t chaining_value[CTR_DRBG_BLOCK_BYTES] = {0};
    uint8_t input_block[CTR_DRBG_BLOCK_BYTES] = {0};
    uint8_t encrypted_block[CTR_DRBG_BLOCK_BYTES] = {0};

    if (key == NULL ||
        data == NULL ||
        output == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (data_len == 0 ||
        data_len % CTR_DRBG_BLOCK_BYTES != 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    for (size_t offset = 0;
         offset < data_len;
         offset += CTR_DRBG_BLOCK_BYTES)
    {
        for (size_t i = 0;
             i < CTR_DRBG_BLOCK_BYTES;
             ++i)
        {
            input_block[i] =
                chaining_value[i] ^
                data[offset + i];
        }

        status = encrypt_block(
            key,
            input_block,
            encrypted_block);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        memcpy(
            chaining_value,
            encrypted_block,
            sizeof(chaining_value));
    }

    memcpy(
        output,
        chaining_value,
        CTR_DRBG_BLOCK_BYTES);

cleanup:

    secure_zero(
        chaining_value,
        sizeof(chaining_value));

    secure_zero(
        input_block,
        sizeof(input_block));

    secure_zero(
        encrypted_block,
        sizeof(encrypted_block));

    return status;
}