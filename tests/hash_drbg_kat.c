#include "drbg.h"
#include "hash_drbg.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This file assumes hash_drbg.h declares:
 *
 *     extern const DRBG HashDRBG;
 *
 * If your descriptor uses a different symbol, change HashDRBG below.
 */

static bool expect_bytes(
    const char *name,
    const uint8_t *actual,
    const uint8_t *expected,
    size_t length)
{
    if (memcmp(actual, expected, length) == 0)
    {
        return true;
    }

    fprintf(stderr, "    %s failed\n", name);

    for (size_t i = 0; i < length; ++i)
    {
        if (actual[i] != expected[i])
        {
            fprintf(
                stderr,
                "    first difference at byte %zu: got %02X, expected %02X\n",
                i,
                actual[i],
                expected[i]);

            break;
        }
    }

    return false;
}

static bool expect_zeroed(
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
                "    context was not zeroized at byte %zu\n",
                i);

            return false;
        }
    }

    return true;
}

bool test_hash_drbg_kat(void)
{
    static const uint8_t entropy[32] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static const uint8_t nonce[16] =
    {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };

    static const uint8_t personalization[16] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };

    static const uint8_t reseed_entropy[32] =
    {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };

    static const uint8_t reseed_additional[16] =
    {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
    };

    static const uint8_t expected_first[64] =
    {
        0x21, 0xE4, 0xEA, 0x60, 0xB4, 0x9A, 0x65, 0xA3,
        0x01, 0xDF, 0xAB, 0xC3, 0x22, 0x06, 0xDD, 0x28,
        0x52, 0xCE, 0xB6, 0x73, 0xCE, 0x88, 0x98, 0x48,
        0x63, 0x07, 0xC0, 0x4A, 0x89, 0x3A, 0xB3, 0xDA,
        0x4A, 0x44, 0x13, 0x18, 0x66, 0xB6, 0x4C, 0x81,
        0xB8, 0xCB, 0xC2, 0x31, 0x56, 0xA6, 0xA9, 0x6D,
        0xDA, 0xB7, 0xAA, 0x62, 0xE2, 0xEA, 0x64, 0x48,
        0x94, 0x39, 0xB2, 0x10, 0x28, 0xEF, 0x9A, 0x4E
    };

    static const uint8_t expected_second[64] =
    {
        0x1C, 0x83, 0xEA, 0xC5, 0x10, 0x59, 0x4C, 0x10,
        0x95, 0x33, 0x3B, 0xF2, 0x82, 0x12, 0x53, 0x4C,
        0x01, 0xF6, 0xB3, 0x19, 0xFC, 0x81, 0x60, 0xA2,
        0xCD, 0x24, 0x7C, 0x52, 0x32, 0xF5, 0x8D, 0xD7,
        0x76, 0x75, 0x55, 0xCE, 0x8C, 0x95, 0x00, 0x76,
        0xE5, 0x06, 0xEA, 0x95, 0xA9, 0xF9, 0xFB, 0xB0,
        0xEB, 0x50, 0xA0, 0xE7, 0x4E, 0x0B, 0x04, 0x4D,
        0xF4, 0x00, 0xA8, 0xCB, 0x9D, 0xB3, 0x40, 0xDD
    };

    static const uint8_t expected_after_reseed[64] =
    {
        0x77, 0x4D, 0xE4, 0xC4, 0x42, 0xD2, 0x42, 0xA2,
        0x64, 0x84, 0x51, 0x54, 0xF6, 0x0E, 0xB7, 0xB9,
        0xFC, 0xFC, 0x7B, 0x37, 0x54, 0xD3, 0xC2, 0x1C,
        0x07, 0x95, 0xDB, 0x75, 0x32, 0xEB, 0xD4, 0xA9,
        0x1A, 0x45, 0x5E, 0xF0, 0xC1, 0x2E, 0xA2, 0x63,
        0xC9, 0xEF, 0x55, 0x5B, 0x21, 0x74, 0x2F, 0xBF,
        0x43, 0x38, 0xC6, 0x6D, 0x6E, 0xE2, 0x7B, 0xFC,
        0xC6, 0x3C, 0x96, 0x08, 0xCB, 0x22, 0xC9, 0xF6
    };

    bool passed = false;
    void *ctx = NULL;

    uint8_t first[sizeof(expected_first)] = {0};
    uint8_t second[sizeof(expected_second)] = {0};
    uint8_t after_reseed[sizeof(expected_after_reseed)] = {0};

    if (HashDRBG.context_size == 0 ||
        HashDRBG.instantiate == NULL ||
        HashDRBG.generate == NULL ||
        HashDRBG.reseed == NULL ||
        HashDRBG.uninstantiate == NULL)
    {
        fprintf(stderr, "    incomplete HashDRBG descriptor\n");
        return false;
    }

    ctx = calloc(1, HashDRBG.context_size);

    if (ctx == NULL)
    {
        fprintf(stderr, "    failed to allocate Hash_DRBG context\n");
        return false;
    }

    DRBGStatus status =
        HashDRBG.instantiate(
            ctx,
            entropy,
            sizeof(entropy),
            nonce,
            sizeof(nonce),
            personalization,
            sizeof(personalization));

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    instantiate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    status =
        HashDRBG.generate(
            ctx,
            first,
            sizeof(first),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    first generate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    if (!expect_bytes(
            "first generate",
            first,
            expected_first,
            sizeof(first)))
    {
        goto cleanup;
    }

    status =
        HashDRBG.generate(
            ctx,
            second,
            sizeof(second),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    second generate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    if (!expect_bytes(
            "second generate",
            second,
            expected_second,
            sizeof(second)))
    {
        goto cleanup;
    }

    if (memcmp(first, second, sizeof(first)) == 0)
    {
        fprintf(
            stderr,
            "    consecutive outputs were identical\n");

        goto cleanup;
    }

    status =
        HashDRBG.reseed(
            ctx,
            reseed_entropy,
            sizeof(reseed_entropy),
            reseed_additional,
            sizeof(reseed_additional));

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    reseed returned status %d\n",
            (int)status);

        goto cleanup;
    }

    status =
        HashDRBG.generate(
            ctx,
            after_reseed,
            sizeof(after_reseed),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    generate after reseed returned status %d\n",
            (int)status);

        goto cleanup;
    }

    if (!expect_bytes(
            "generate after reseed",
            after_reseed,
            expected_after_reseed,
            sizeof(after_reseed)))
    {
        goto cleanup;
    }

    HashDRBG.uninstantiate(ctx);

    if (!expect_zeroed(
            ctx,
            HashDRBG.context_size))
    {
        goto cleanup_without_uninstantiate;
    }

    passed = true;
    goto cleanup_without_uninstantiate;

cleanup:

    HashDRBG.uninstantiate(ctx);

cleanup_without_uninstantiate:

    free(ctx);
    return passed;
}