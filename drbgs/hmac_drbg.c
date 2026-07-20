#include "hmac_drbg.h"

#include "hmac_drbg_update.h"
#include "status.h"
#include "utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static DRBGStatus hmac_instantiate(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *personalization,
    size_t personalization_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    HMACDRBGContext *context = NULL;

    uint8_t *seed_material = NULL;
    size_t seed_material_len = 0;
    size_t offset = 0;

    uint8_t working_K[HMAC_DRBG_OUTLEN_BYTES];
    uint8_t working_V[HMAC_DRBG_OUTLEN_BYTES];

    if (ctx == NULL ||
        entropy == NULL ||
        nonce == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (entropy_len < HMAC_DRBG_ENTROPY_BYTES ||
        nonce_len < HMAC_DRBG_NONCE_BYTES)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (personalization_len > 0 &&
        personalization == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (entropy_len >
        SIZE_MAX - nonce_len)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    seed_material_len =
        entropy_len + nonce_len;

    if (personalization_len >
        SIZE_MAX - seed_material_len)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    seed_material_len +=
        personalization_len;

    seed_material =
        malloc(seed_material_len);

    if (seed_material == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    memcpy(
        seed_material + offset,
        entropy,
        entropy_len);

    offset += entropy_len;

    memcpy(
        seed_material + offset,
        nonce,
        nonce_len);

    offset += nonce_len;

    if (personalization_len > 0)
    {
        memcpy(
            seed_material + offset,
            personalization,
            personalization_len);

        offset += personalization_len;
    }

    if (offset != seed_material_len)
    {
        status = DRBG_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    memset(
        working_K,
        0x00,
        sizeof(working_K));

    memset(
        working_V,
        0x01,
        sizeof(working_V));

    status = hmac_drbg_update(
        working_K,
        working_V,
        seed_material,
        seed_material_len);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    context =
        (HMACDRBGContext *)ctx;

    memcpy(
        context->K,
        working_K,
        sizeof(context->K));

    memcpy(
        context->V,
        working_V,
        sizeof(context->V));

    context->reseed_counter = 1;

cleanup:

    secure_zero(
        working_K,
        sizeof(working_K));

    secure_zero(
        working_V,
        sizeof(working_V));

    if (seed_material != NULL)
    {
        secure_zero(
            seed_material,
            seed_material_len);

        free(seed_material);
    }

    return status;
}

static void hmac_uninstantiate(
    void *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    secure_zero(
        ctx,
        sizeof(HMACDRBGContext));
}