#include "drbg.h"
#include "hmac_drbg.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool expect_status(
    const char *name,
    DRBGStatus actual,
    DRBGStatus expected)
{
    if (actual == expected)
    {
        return true;
    }

    fprintf(
        stderr,
        "    %s: got status %d, expected %d\n",
        name,
        (int)actual,
        (int)expected);

    return false;
}

static bool expect_unchanged(
    const char *name,
    const void *actual,
    const void *before,
    size_t length)
{
    if (memcmp(actual, before, length) == 0)
    {
        return true;
    }

    fprintf(
        stderr,
        "    %s modified HMAC_DRBG state on failure\n",
        name);

    return false;
}

static bool expect_zeroed(
    const char *name,
    const void *memory,
    size_t length)
{
    const uint8_t *bytes =
        (const uint8_t *)memory;

    for (size_t i = 0; i < length; ++i)
    {
        if (bytes[i] != 0)
        {
            fprintf(
                stderr,
                "    %s: nonzero context byte at offset %zu\n",
                name,
                i);

            return false;
        }
    }

    return true;
}

bool test_hmac_drbg_boundaries(void)
{
    static const uint8_t entropy[HMAC_DRBG_ENTROPY_BYTES] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static const uint8_t nonce[HMAC_DRBG_NONCE_BYTES] =
    {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };

    bool passed = false;

    void *ctx = NULL;
    void *state_before = NULL;
    uint8_t *output = NULL;

    if (HMACDRBG.context_size < sizeof(HMACDRBGContext) ||
        HMACDRBG.instantiate == NULL ||
        HMACDRBG.generate == NULL ||
        HMACDRBG.reseed == NULL ||
        HMACDRBG.uninstantiate == NULL)
    {
        fprintf(stderr, "    incomplete HMACDRBG descriptor\n");
        return false;
    }

    ctx = calloc(1, HMACDRBG.context_size);
    state_before = malloc(HMACDRBG.context_size);

    output =
        malloc(HMAC_DRBG_MAX_BYTES_PER_REQUEST + 1U);

    if (ctx == NULL ||
        state_before == NULL ||
        output == NULL)
    {
        fprintf(stderr, "    HMAC_DRBG boundary allocation failed\n");
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    DRBGStatus status =
        HMACDRBG.instantiate(
            ctx,
            entropy,
            HMAC_DRBG_ENTROPY_BYTES - 1U,
            nonce,
            sizeof(nonce),
            NULL,
            0);

    if (!expect_status(
            "insufficient instantiate entropy",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "insufficient instantiate entropy",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.instantiate(
            ctx,
            entropy,
            sizeof(entropy),
            nonce,
            HMAC_DRBG_NONCE_BYTES - 1U,
            NULL,
            0);

    if (!expect_status(
            "insufficient nonce",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "insufficient nonce",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    status =
        HMACDRBG.instantiate(
            ctx,
            entropy,
            sizeof(entropy),
            nonce,
            sizeof(nonce),
            NULL,
            0);

    if (!expect_status(
            "valid instantiate",
            status,
            DRBG_STATUS_SUCCESS))
    {
        goto cleanup;
    }

    status =
        HMACDRBG.generate(
            ctx,
            output,
            HMAC_DRBG_MAX_BYTES_PER_REQUEST,
            NULL,
            0);

    if (!expect_status(
            "maximum-size generate",
            status,
            DRBG_STATUS_SUCCESS))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.generate(
            ctx,
            output,
            HMAC_DRBG_MAX_BYTES_PER_REQUEST + 1U,
            NULL,
            0);

    if (!expect_status(
            "oversized generate",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "oversized generate",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.generate(
            ctx,
            NULL,
            1,
            NULL,
            0);

    if (!expect_status(
            "NULL output",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "NULL output",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.generate(
            ctx,
            output,
            0,
            NULL,
            0);

    if (!expect_status(
            "zero-length output",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "zero-length output",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.generate(
            ctx,
            output,
            1,
            NULL,
            1);

    if (!expect_status(
            "NULL generate additional input",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "NULL generate additional input",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.reseed(
            ctx,
            entropy,
            HMAC_DRBG_ENTROPY_BYTES - 1U,
            NULL,
            0);

    if (!expect_status(
            "insufficient reseed entropy",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "insufficient reseed entropy",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.reseed(
            ctx,
            entropy,
            sizeof(entropy),
            NULL,
            1);

    if (!expect_status(
            "NULL reseed additional input",
            status,
            DRBG_STATUS_INVALID_ARGUMENT) ||
        !expect_unchanged(
            "NULL reseed additional input",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    status =
        HMACDRBG.reseed(
            ctx,
            entropy,
            sizeof(entropy),
            NULL,
            0);

    if (!expect_status(
            "valid reseed",
            status,
            DRBG_STATUS_SUCCESS))
    {
        goto cleanup;
    }

    HMACDRBGContext *hmac_ctx =
        (HMACDRBGContext *)ctx;

    if (hmac_ctx->reseed_counter != UINT64_C(1))
    {
        fprintf(
            stderr,
            "    valid reseed set counter to %llu, expected 1\n",
            (unsigned long long)hmac_ctx->reseed_counter);

        goto cleanup;
    }

    hmac_ctx->reseed_counter =
        HMAC_DRBG_RESEED_INTERVAL;

    status =
        HMACDRBG.generate(
            ctx,
            output,
            1,
            NULL,
            0);

    if (!expect_status(
            "generate at reseed interval",
            status,
            DRBG_STATUS_SUCCESS))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HMACDRBG.context_size);

    status =
        HMACDRBG.generate(
            ctx,
            output,
            1,
            NULL,
            0);

    if (!expect_status(
            "generate beyond reseed interval",
            status,
            DRBG_STATUS_RESEED_REQUIRED) ||
        !expect_unchanged(
            "generate beyond reseed interval",
            ctx,
            state_before,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    HMACDRBG.uninstantiate(ctx);

    if (!expect_zeroed(
            "uninstantiate",
            ctx,
            HMACDRBG.context_size))
    {
        goto cleanup;
    }

    passed = true;

cleanup:

    if (ctx != NULL)
    {
        HMACDRBG.uninstantiate(ctx);
    }

    if (output != NULL)
    {
        memset(
            output,
            0,
            HMAC_DRBG_MAX_BYTES_PER_REQUEST + 1U);
    }

    free(output);
    free(state_before);
    free(ctx);

    return passed;
}