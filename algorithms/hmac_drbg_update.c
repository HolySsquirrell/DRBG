#include "hmac_drbg_update.h"

#include "crypto_hmac.h"
#include "utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static DRBGStatus update_round(
    uint8_t K[HMAC_DRBG_OUTLEN_BYTES],
    uint8_t V[HMAC_DRBG_OUTLEN_BYTES],
    uint8_t separator,
    const uint8_t *provided_data,
    size_t provided_data_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t *input = NULL;
    size_t input_len = 0;

    uint8_t new_K[HMAC_DRBG_OUTLEN_BYTES] = {0};
    uint8_t new_V[HMAC_DRBG_OUTLEN_BYTES] = {0};

    if (K == NULL || V == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (provided_data_len > 0 &&
        provided_data == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (provided_data_len >
        SIZE_MAX - HMAC_DRBG_OUTLEN_BYTES - 1U)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    input_len =
        HMAC_DRBG_OUTLEN_BYTES +
        1U +
        provided_data_len;

    input = malloc(input_len);

    if (input == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    memcpy(
        input,
        V,
        HMAC_DRBG_OUTLEN_BYTES);

    input[HMAC_DRBG_OUTLEN_BYTES] =
        separator;

    if (provided_data_len > 0)
    {
        memcpy(
            input + HMAC_DRBG_OUTLEN_BYTES + 1U,
            provided_data,
            provided_data_len);
    }
    status = crypto_hmac_sha256(
        K,
        HMAC_DRBG_OUTLEN_BYTES,
        input,
        input_len,
        new_K);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = crypto_hmac_sha256(
        new_K,
        HMAC_DRBG_OUTLEN_BYTES,
        V,
        HMAC_DRBG_OUTLEN_BYTES,
        new_V);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    memcpy(
        K,
        new_K,
        HMAC_DRBG_OUTLEN_BYTES);

    memcpy(
        V,
        new_V,
        HMAC_DRBG_OUTLEN_BYTES);

cleanup:

    secure_zero(
        new_K,
        sizeof(new_K));

    secure_zero(
        new_V,
        sizeof(new_V));

    if (input != NULL)
    {
        secure_zero(
            input,
            input_len);

        free(input);
    }

    return status;
}

DRBGStatus hmac_drbg_update(
    uint8_t K[HMAC_DRBG_OUTLEN_BYTES],
    uint8_t V[HMAC_DRBG_OUTLEN_BYTES],
    const uint8_t *provided_data,
    size_t provided_data_len)
{
    if (K == NULL || V == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (provided_data_len > 0 &&
        provided_data == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    DRBGStatus status =
        update_round(
            K,
            V,
            0x00,
            provided_data,
            provided_data_len);

    if (status != DRBG_STATUS_SUCCESS)
    {
        return status;
    }

    if (provided_data == NULL ||
        provided_data_len == 0)
    {
        return DRBG_STATUS_SUCCESS;
    }

    return update_round(
        K,
        V,
        0x01,
        provided_data,
        provided_data_len);
}