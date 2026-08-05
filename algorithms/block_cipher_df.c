#include "block_cipher_df.h"

#include "crypto_aes.h"
#include "ctr_drbg_bcc.h"
#include "utils.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void write_u32_be(
    uint8_t output[4],
    uint32_t value)
{
    output[0] =
        (uint8_t)(value >> 24);

    output[1] =
        (uint8_t)(value >> 16);

    output[2] =
        (uint8_t)(value >> 8);

    output[3] =
        (uint8_t)value;
}

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

DRBGStatus block_cipher_df(
    const uint8_t *input,
    size_t input_len,
    uint8_t output[CTR_DRBG_SEED_BYTES])
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t initial_key[CTR_DRBG_KEY_BYTES] = {0};
    uint8_t temp[CTR_DRBG_SEED_BYTES] = {0};

    uint8_t derived_key[CTR_DRBG_KEY_BYTES] = {0};
    uint8_t x[CTR_DRBG_BLOCK_BYTES] = {0};
    uint8_t result[CTR_DRBG_SEED_BYTES] = {0};

    uint8_t *bcc_input = NULL;

    size_t unpadded_s_len = 0;
    size_t padding_len = 0;
    size_t s_len = 0;
    size_t bcc_input_len = 0;

    if (output == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (input_len > 0 &&
        input == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (input_len > UINT32_MAX)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }


    if (input_len > SIZE_MAX - 9U)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    unpadded_s_len =
        8U + input_len + 1U;

    padding_len =
        (CTR_DRBG_BLOCK_BYTES -
         (unpadded_s_len % CTR_DRBG_BLOCK_BYTES))
        % CTR_DRBG_BLOCK_BYTES;

    if (unpadded_s_len >
        SIZE_MAX - padding_len)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    s_len =
        unpadded_s_len + padding_len;

    if (s_len >
        SIZE_MAX - CTR_DRBG_BLOCK_BYTES)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    bcc_input_len =
        CTR_DRBG_BLOCK_BYTES + s_len;

    bcc_input =
        calloc(1, bcc_input_len);

    if (bcc_input == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    for (size_t i = 0;
         i < CTR_DRBG_KEY_BYTES;
         ++i)
    {
        initial_key[i] =
            (uint8_t)i;
    }

    write_u32_be(
        bcc_input + CTR_DRBG_BLOCK_BYTES,
        (uint32_t)input_len);

    write_u32_be(
        bcc_input + CTR_DRBG_BLOCK_BYTES + 4U,
        (uint32_t)CTR_DRBG_SEED_BYTES);

    if (input_len > 0)
    {
        memcpy(
            bcc_input + CTR_DRBG_BLOCK_BYTES + 8U,
            input,
            input_len);
    }

    bcc_input[
        CTR_DRBG_BLOCK_BYTES +
        8U +
        input_len] = 0x80U;

    for (size_t round = 0;
         round <
             CTR_DRBG_SEED_BYTES /
             CTR_DRBG_BLOCK_BYTES;
         ++round)
    {

        memset(
            bcc_input,
            0,
            CTR_DRBG_BLOCK_BYTES);

        write_u32_be(
            bcc_input,
            (uint32_t)round);

        status = ctr_drbg_bcc(
            initial_key,
            bcc_input,
            bcc_input_len,
            temp +
                round *
                CTR_DRBG_BLOCK_BYTES);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    memcpy(
        derived_key,
        temp,
        sizeof(derived_key));

    memcpy(
        x,
        temp + CTR_DRBG_KEY_BYTES,
        sizeof(x));

    for (size_t offset = 0;
         offset < CTR_DRBG_SEED_BYTES;
         offset += CTR_DRBG_BLOCK_BYTES)
    {
        uint8_t encrypted_x[CTR_DRBG_BLOCK_BYTES] = {0};

        status = encrypt_block(
            derived_key,
            x,
            encrypted_x);

        if (status != DRBG_STATUS_SUCCESS)
        {
            secure_zero(
                encrypted_x,
                sizeof(encrypted_x));

            goto cleanup;
        }

        memcpy(
            x,
            encrypted_x,
            sizeof(x));

        memcpy(
            result + offset,
            encrypted_x,
            sizeof(encrypted_x));

        secure_zero(
            encrypted_x,
            sizeof(encrypted_x));
    }
    memcpy(
        output,
        result,
        CTR_DRBG_SEED_BYTES);

cleanup:

    if (bcc_input != NULL)
    {
        secure_zero(
            bcc_input,
            bcc_input_len);

        free(bcc_input);
    }

    secure_zero(
        initial_key,
        sizeof(initial_key));

    secure_zero(
        temp,
        sizeof(temp));

    secure_zero(
        derived_key,
        sizeof(derived_key));

    secure_zero(
        x,
        sizeof(x));

    secure_zero(
        result,
        sizeof(result));

    return status;
}