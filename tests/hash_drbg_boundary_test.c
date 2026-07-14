#include "drbg.h"
#include "hash_drbg.h"
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
        "    %s modified the DRBG state on failure\n",
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

bool test_hash_drbg_boundaries(void)
{
    static const uint8_t entropy[HASH_DRBG_ENTROPY_BYTES] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static const uint8_t nonce[HASH_DRBG_NONCE_BYTES] =
    {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };

    bool passed = false;

    void *ctx = NULL;
    void *state_before = NULL;
    uint8_t *output = NULL;

    if (HashDRBG.context_size < sizeof(HashDRBGContext) ||
        HashDRBG.instantiate == NULL ||
        HashDRBG.generate == NULL ||
        HashDRBG.reseed == NULL ||
        HashDRBG.uninstantiate == NULL)
    {
        fprintf(stderr, "    incomplete or inconsistent HashDRBG descriptor\n");
        return false;
    }

    ctx = calloc(1, HashDRBG.context_size);
    state_before = malloc(HashDRBG.context_size);

    output =
        malloc(HASH_DRBG_MAX_BYTES_PER_REQUEST + 1U);

    if (ctx == NULL ||
        state_before == NULL ||
        output == NULL)
    {
        fprintf(stderr, "    boundary-test allocation failed\n");
        goto cleanup;
    }

    /*
     * Insufficient instantiate entropy must be rejected without
     * modifying the zeroed context.
     */
    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    DRBGStatus status =
        HashDRBG.instantiate(
            ctx,
            entropy,
            HASH_DRBG_ENTROPY_BYTES - 1U,
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    status =
        HashDRBG.instantiate(
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

    /*
     * The maximum permitted request must succeed.
     */
    status =
        HashDRBG.generate(
            ctx,
            output,
            HASH_DRBG_MAX_BYTES_PER_REQUEST,
            NULL,
            0);

    if (!expect_status(
            "maximum-size generate",
            status,
            DRBG_STATUS_SUCCESS))
    {
        goto cleanup;
    }

    /*
     * One byte beyond the maximum must fail and preserve state.
     */
    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.generate(
            ctx,
            output,
            HASH_DRBG_MAX_BYTES_PER_REQUEST + 1U,
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.generate(
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.generate(
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.generate(
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    /*
     * Failed reseeds must preserve V, C and reseed_counter.
     */
    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.reseed(
            ctx,
            entropy,
            HASH_DRBG_ENTROPY_BYTES - 1U,
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    memcpy(
        state_before,
        ctx,
        HashDRBG.context_size);

    status =
        HashDRBG.reseed(
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    /*
     * A successful reseed resets the counter to one.
     */
    status =
        HashDRBG.reseed(
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

    HashDRBGContext *hash_ctx =
        (HashDRBGContext *)ctx;

    if (hash_ctx->reseed_counter != UINT64_C(1))
    {
        fprintf(
            stderr,
            "    valid reseed set counter to %llu, expected 1\n",
            (unsigned long long)hash_ctx->reseed_counter);

        goto cleanup;
    }

    /*
     * The request at exactly reseed_interval is permitted. It advances
     * the counter beyond the interval, so the following request must
     * return RESEED_REQUIRED without changing state.
     */
    hash_ctx->reseed_counter =
        HASH_DRBG_RESEED_INTERVAL;

    status =
        HashDRBG.generate(
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
        HashDRBG.context_size);

    status =
        HashDRBG.generate(
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
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    /*
     * Uninstantiate must erase the complete implementation context.
     */
    HashDRBG.uninstantiate(ctx);

    if (!expect_zeroed(
            "uninstantiate",
            ctx,
            HashDRBG.context_size))
    {
        goto cleanup;
    }

    passed = true;

cleanup:

    if (ctx != NULL)
    {
        HashDRBG.uninstantiate(ctx);
    }

    if (output != NULL)
    {
        memset(
            output,
            0,
            HASH_DRBG_MAX_BYTES_PER_REQUEST + 1U);
    }

    free(output);
    free(state_before);
    free(ctx);

    return passed;
}