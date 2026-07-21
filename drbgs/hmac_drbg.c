#include "hmac_drbg.h"

#include "crypto_hmac.h"
#include "hmac_drbg_update.h"
#include "status.h"
#include "utils.h"

#include <stddef.h>
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

static DRBGStatus hmac_reseed(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    HMACDRBGContext *context = NULL;

    uint8_t *seed_material = NULL;
    size_t seed_material_len = 0;

    uint8_t working_K[HMAC_DRBG_OUTLEN_BYTES] = {0};
    uint8_t working_V[HMAC_DRBG_OUTLEN_BYTES] = {0};

    if (ctx == NULL ||
        entropy == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (entropy_len < HMAC_DRBG_ENTROPY_BYTES)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (additional_len > 0 &&
        additional_input == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (additional_len >
        SIZE_MAX - entropy_len)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    seed_material_len =
        entropy_len + additional_len;

    seed_material =
        malloc(seed_material_len);

    if (seed_material == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    memcpy(
        seed_material,
        entropy,
        entropy_len);

    if (additional_len > 0)
    {
        memcpy(
            seed_material + entropy_len,
            additional_input,
            additional_len);
    }

    context =
        (HMACDRBGContext *)ctx;

    memcpy(
        working_K,
        context->K,
        sizeof(working_K));

    memcpy(
        working_V,
        context->V,
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

static DRBGStatus hmac_generate(
    void *ctx,
    uint8_t *output,
    size_t output_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    HMACDRBGContext *context = NULL;

    uint8_t working_K[HMAC_DRBG_OUTLEN_BYTES] = {0};
    uint8_t working_V[HMAC_DRBG_OUTLEN_BYTES] = {0};

    uint8_t generated_block[HMAC_DRBG_OUTLEN_BYTES] = {0};

    size_t produced = 0;

    if (ctx == NULL ||
        output == NULL ||
        output_len == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (additional_len > 0 &&
        additional_input == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (output_len >
        HMAC_DRBG_MAX_BYTES_PER_REQUEST)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    context =
        (HMACDRBGContext *)ctx;

    if (context->reseed_counter >
        HMAC_DRBG_RESEED_INTERVAL)
    {
        return DRBG_STATUS_RESEED_REQUIRED;
    }

    memcpy(
        working_K,
        context->K,
        sizeof(working_K));

    memcpy(
        working_V,
        context->V,
        sizeof(working_V));

    if (additional_len > 0)
    {
        status = hmac_drbg_update(
            working_K,
            working_V,
            additional_input,
            additional_len);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }
    while (produced < output_len)
    {
        status = crypto_hmac_sha256(
            working_K,
            sizeof(working_K),
            working_V,
            sizeof(working_V),
            generated_block);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        memcpy(
            working_V,
            generated_block,
            sizeof(working_V));

        size_t remaining =
            output_len - produced;

        size_t copy_length =
            remaining < sizeof(generated_block)
                ? remaining
                : sizeof(generated_block);

        memcpy(
            output + produced,
            generated_block,
            copy_length);

        produced += copy_length;
    }

    status = hmac_drbg_update(
        working_K,
        working_V,
        additional_input,
        additional_len);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    memcpy(
        context->K,
        working_K,
        sizeof(context->K));

    memcpy(
        context->V,
        working_V,
        sizeof(context->V));

    context->reseed_counter++;

cleanup:

    if (status != DRBG_STATUS_SUCCESS)
    {
        secure_zero(
            output,
            output_len);
    }

    secure_zero(
        generated_block,
        sizeof(generated_block));

    secure_zero(
        working_K,
        sizeof(working_K));

    secure_zero(
        working_V,
        sizeof(working_V));

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

const DRBG HMACDRBG =
{
    .name = "HMAC_DRBG",

    .context_size =
        sizeof(HMACDRBGContext),

    .max_request_size =
        HMAC_DRBG_MAX_BYTES_PER_REQUEST,

    .instantiate =
        hmac_instantiate,

    .generate =
        hmac_generate,

    .reseed =
        hmac_reseed,

    .verify = NULL,

    .uninstantiate =
        hmac_uninstantiate
};