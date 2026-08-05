#include "ctr_drbg_update.h"

#include "crypto_aes.h"
#include "ctr_drbg_counter.h"
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

DRBGStatus ctr_drbg_update(
    uint8_t key[CTR_DRBG_KEY_BYTES],
    uint8_t v[CTR_DRBG_BLOCK_BYTES],
    const uint8_t provided_data[CTR_DRBG_SEED_BYTES])
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t working_v[CTR_DRBG_BLOCK_BYTES] = {0};
    uint8_t temp[CTR_DRBG_SEED_BYTES] = {0};

    uint8_t new_key[CTR_DRBG_KEY_BYTES] = {0};
    uint8_t new_v[CTR_DRBG_BLOCK_BYTES] = {0};

    if (key == NULL ||
        v == NULL ||
        provided_data == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    memcpy(
        working_v,
        v,
        sizeof(working_v));

    for (size_t offset = 0;
         offset < CTR_DRBG_SEED_BYTES;
         offset += CTR_DRBG_BLOCK_BYTES)
    {
        ctr_drbg_increment(working_v);

        status = encrypt_block(
            key,
            working_v,
            temp + offset);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    for (size_t i = 0;
         i < CTR_DRBG_SEED_BYTES;
         ++i)
    {
        temp[i] ^= provided_data[i];
    }

    memcpy(
        new_key,
        temp,
        sizeof(new_key));

    memcpy(
        new_v,
        temp + CTR_DRBG_KEY_BYTES,
        sizeof(new_v));

    memcpy(
        key,
        new_key,
        sizeof(new_key));

    memcpy(
        v,
        new_v,
        sizeof(new_v));

cleanup:

    secure_zero(
        working_v,
        sizeof(working_v));

    secure_zero(
        temp,
        sizeof(temp));

    secure_zero(
        new_key,
        sizeof(new_key));

    secure_zero(
        new_v,
        sizeof(new_v));

    return status;
}