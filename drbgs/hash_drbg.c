#include "hash_drbg.h"

#include "crypto_hash.h"
#include "hash_df.h"
#include "hash_math.h"
#include "hashgen.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void hash_secure_zero(
    void *memory,
    size_t length)
{
    volatile uint8_t *bytes =
        (volatile uint8_t *)memory;

    while (length > 0)
    {
        *bytes = 0;

        ++bytes;
        --length;
    }
}


static DRBGStatus hash_instantiate(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *personalization,
    size_t personalization_len)
{
    if (ctx == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (entropy == NULL || entropy_len == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }
    if (entropy_len < HASH_DRBG_ENTROPY_BYTES)
        return DRBG_STATUS_INVALID_ARGUMENT;

    if (nonce_len < HASH_DRBG_NONCE_BYTES)
        return DRBG_STATUS_INVALID_ARGUMENT;

    HashDRBGContext *context = (HashDRBGContext *)ctx;

    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t *seed_material = NULL;

    size_t seed_material_len =
        entropy_len +
        nonce_len +
        personalization_len;

    seed_material = malloc(seed_material_len);

    if (seed_material == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    size_t offset = 0;

    memcpy(
        seed_material + offset,
        entropy,
        entropy_len);

    offset += entropy_len;

    if (nonce != NULL)
    {
        memcpy(
            seed_material + offset,
            nonce,
            nonce_len);

        offset += nonce_len;
    }

    if (personalization != NULL &&
        personalization_len > 0)
    {
        memcpy(
            seed_material + offset,
            personalization,
            personalization_len);
    }

    status = hash_df(
        seed_material,
        seed_material_len,
        context->V,
        HASH_DRBG_SEEDLEN_BYTES);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    uint8_t c_input[1 + HASH_DRBG_SEEDLEN_BYTES];

    c_input[0] = 0x00;

    memcpy(
        c_input + 1,
        context->V,
        HASH_DRBG_SEEDLEN_BYTES);

    status = hash_df(
        c_input,
        sizeof(c_input),
        context->C,
        HASH_DRBG_SEEDLEN_BYTES);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    context->reseed_counter = 1;

cleanup:

    free(seed_material);

    return status;
}

static DRBGStatus hash_generate(
    void *ctx,
    uint8_t *output,
    size_t output_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    HashDRBGContext *context = NULL;

    uint8_t working_V[HASH_DRBG_SEEDLEN_BYTES];
    uint8_t w[SHA256_DIGEST_SIZE];
    uint8_t H[SHA256_DIGEST_SIZE];

    uint8_t h_input[1 + HASH_DRBG_SEEDLEN_BYTES];

    uint8_t *w_input = NULL;
    size_t w_input_len = 0;

    if (ctx == NULL || output == NULL || output_len == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (additional_len > 0 && additional_input == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (output_len > HASH_DRBG_MAX_BYTES_PER_REQUEST)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    context = (HashDRBGContext *)ctx;

    if (context->reseed_counter > HASH_DRBG_RESEED_INTERVAL)
    {
        return DRBG_STATUS_RESEED_REQUIRED;
    }

    memset(working_V, 0, sizeof(working_V));
    memset(w, 0, sizeof(w));
    memset(H, 0, sizeof(H));

    memcpy(
        working_V,
        context->V,
        sizeof(working_V));

    if (additional_input != NULL && additional_len > 0)
    {
        if (additional_len >
            SIZE_MAX - (1U + HASH_DRBG_SEEDLEN_BYTES))
        {
            status = DRBG_STATUS_INVALID_ARGUMENT;
            goto cleanup;
        }

        w_input_len =
            1U +
            HASH_DRBG_SEEDLEN_BYTES +
            additional_len;

        w_input = malloc(w_input_len);

        if (w_input == NULL)
        {
            status = DRBG_STATUS_MEMORY_ERROR;
            goto cleanup;
        }

        w_input[0] = 0x02;

        memcpy(
            w_input + 1,
            working_V,
            HASH_DRBG_SEEDLEN_BYTES);

        memcpy(
            w_input + 1 + HASH_DRBG_SEEDLEN_BYTES,
            additional_input,
            additional_len);

        status = crypto_sha256(
            w_input,
            w_input_len,
            w);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        status = hash_math_add_bytes(
            working_V,
            sizeof(working_V),
            w,
            sizeof(w));

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    status = hashgen(
        working_V,
        output,
        output_len);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    h_input[0] = 0x03;

    memcpy(
        h_input + 1,
        working_V,
        HASH_DRBG_SEEDLEN_BYTES);

    status = crypto_sha256(
        h_input,
        sizeof(h_input),
        H);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = hash_math_add_bytes(
        working_V,
        sizeof(working_V),
        H,
        sizeof(H));

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = hash_math_add_bytes(
        working_V,
        sizeof(working_V),
        context->C,
        sizeof(context->C));

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = hash_math_add_u64(
        working_V,
        sizeof(working_V),
        context->reseed_counter);

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    memcpy(
        context->V,
        working_V,
        sizeof(context->V));

    context->reseed_counter++;

cleanup:

    if (status != DRBG_STATUS_SUCCESS)
    {
        hash_secure_zero(
            output,
            output_len);
    }

    if (w_input != NULL)
    {
        hash_secure_zero(
            w_input,
            w_input_len);

        free(w_input);
    }

    hash_secure_zero(
        h_input,
        sizeof(h_input));

    hash_secure_zero(
        H,
        sizeof(H));

    hash_secure_zero(
        w,
        sizeof(w));

    hash_secure_zero(
        working_V,
        sizeof(working_V));

    return status;
}

static DRBGStatus hash_reseed(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    HashDRBGContext *context = NULL;

    uint8_t *seed_material = NULL;
    size_t seed_material_len = 0;
    size_t offset = 0;

    uint8_t new_V[HASH_DRBG_SEEDLEN_BYTES];
    uint8_t new_C[HASH_DRBG_SEEDLEN_BYTES];

    uint8_t c_input[1 + HASH_DRBG_SEEDLEN_BYTES];

    /*
     * Validate required parameters.
     */
    if (ctx == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (entropy == NULL ||
        entropy_len < HASH_DRBG_ENTROPY_BYTES)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (additional_len > 0 &&
        additional_input == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    /*
     * Check that this calculation cannot overflow:
     *
     * 1 byte prefix
     * + V
     * + entropy input
     * + optional additional input
     */
    if (entropy_len >
        SIZE_MAX - 1U - HASH_DRBG_SEEDLEN_BYTES)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    seed_material_len =
        1U +
        HASH_DRBG_SEEDLEN_BYTES +
        entropy_len;

    if (additional_len >
        SIZE_MAX - seed_material_len)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    seed_material_len += additional_len;

    context = (HashDRBGContext *)ctx;

    memset(new_V, 0, sizeof(new_V));
    memset(new_C, 0, sizeof(new_C));
    memset(c_input, 0, sizeof(c_input));

    seed_material = malloc(seed_material_len);

    if (seed_material == NULL)
    {
        status = DRBG_STATUS_MEMORY_ERROR;
        goto cleanup;
    }

    /*
     * seed_material =
     *     0x01 || V || entropy_input || additional_input
     */

    seed_material[offset] = 0x01;
    offset += 1U;

    memcpy(
        seed_material + offset,
        context->V,
        HASH_DRBG_SEEDLEN_BYTES);

    offset += HASH_DRBG_SEEDLEN_BYTES;

    memcpy(
        seed_material + offset,
        entropy,
        entropy_len);

    offset += entropy_len;

    if (additional_input != NULL &&
        additional_len > 0)
    {
        memcpy(
            seed_material + offset,
            additional_input,
            additional_len);

        offset += additional_len;
    }

    /*
     * Defensive consistency check.
     */
    if (offset != seed_material_len)
    {
        status = DRBG_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    /*
     * seed = Hash_df(seed_material, seedlen)
     * V = seed
     *
     * Derive into temporary storage so the current DRBG state
     * remains valid if an operation fails.
     */
    status = hash_df(
        seed_material,
        seed_material_len,
        new_V,
        sizeof(new_V));

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    /*
     * C = Hash_df(0x00 || V, seedlen)
     */
    c_input[0] = 0x00;

    memcpy(
        c_input + 1,
        new_V,
        sizeof(new_V));

    status = hash_df(
        c_input,
        sizeof(c_input),
        new_C,
        sizeof(new_C));

    if (status != DRBG_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    /*
     * Commit the new working state only after all derivation
     * operations have succeeded.
     */
    memcpy(
        context->V,
        new_V,
        sizeof(context->V));

    memcpy(
        context->C,
        new_C,
        sizeof(context->C));

    context->reseed_counter = 1;

cleanup:

    if (seed_material != NULL)
    {
        hash_secure_zero(
            seed_material,
            seed_material_len);

        free(seed_material);
    }

    hash_secure_zero(
        c_input,
        sizeof(c_input));

    hash_secure_zero(
        new_C,
        sizeof(new_C));

    hash_secure_zero(
        new_V,
        sizeof(new_V));

    return status;
}

static void hash_uninstantiate(void *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    hash_secure_zero(
        ctx,
        sizeof(HashDRBGContext));
}

const DRBG HashDRBG =
{
    .name = "Hash_DRBG",

    .context_size = sizeof(HashDRBGContext),
    .max_request_size = HASH_DRBG_MAX_BYTES_PER_REQUEST,

    .instantiate = hash_instantiate,
    .generate = hash_generate,
    .reseed = hash_reseed,
    .verify = NULL,
    .uninstantiate = hash_uninstantiate
};