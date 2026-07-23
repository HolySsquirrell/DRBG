#include "drbg.h"
#include "hmac_drbg.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    fprintf(stderr, "    %s output mismatch\n", name);

    for (size_t i = 0; i < length; ++i)
    {
        if (actual[i] != expected[i])
        {
            fprintf(
                stderr,
                "    first difference at byte %zu: "
                "got %02X, expected %02X\n",
                i,
                actual[i],
                expected[i]);

            break;
        }
    }

    return false;
}

static void clear_output(
    uint8_t *buffer,
    size_t length)
{
    volatile uint8_t *bytes =
        (volatile uint8_t *)buffer;

    while (length > 0)
    {
        *bytes++ = 0;
        --length;
    }
}


bool test_hmac_drbg_nist_kat(void)
{
    static const uint8_t entropy_input[32] =
    {
        0xCA, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xBF,
        0xFE, 0x89, 0xDE, 0x1C, 0xBD, 0xC4, 0x6E, 0x68,
        0x31, 0xE4, 0x4D, 0x34, 0xA4, 0xFB, 0x93, 0x5E,
        0xE2, 0x85, 0xDD, 0x14, 0xB7, 0x1A, 0x74, 0x88
    };

    static const uint8_t nonce[16] =
    {
        0x65, 0x9B, 0xA9, 0x6C, 0x60, 0x1D, 0xC6, 0x9F,
        0xC9, 0x02, 0x94, 0x08, 0x05, 0xEC, 0x0C, 0xA8
    };

    static const uint8_t expected[128] =
    {
        0xE5, 0x28, 0xE9, 0xAB, 0xF2, 0xDE, 0xCE, 0x54,
        0xD4, 0x7C, 0x7E, 0x75, 0xE5, 0xFE, 0x30, 0x21,
        0x49, 0xF8, 0x17, 0xEA, 0x9F, 0xB4, 0xBE, 0xE6,
        0xF4, 0x19, 0x96, 0x97, 0xD0, 0x4D, 0x5B, 0x89,
        0xD5, 0x4F, 0xBB, 0x97, 0x8A, 0x15, 0xB5, 0xC4,
        0x43, 0xC9, 0xEC, 0x21, 0x03, 0x6D, 0x24, 0x60,
        0xB6, 0xF7, 0x3E, 0xBA, 0xD0, 0xDC, 0x2A, 0xBA,
        0x6E, 0x62, 0x4A, 0xBF, 0x07, 0x74, 0x5B, 0xC1,
        0x07, 0x69, 0x4B, 0xB7, 0x54, 0x7B, 0xB0, 0x99,
        0x5F, 0x70, 0xDE, 0x25, 0xD6, 0xB2, 0x9E, 0x2D,
        0x30, 0x11, 0xBB, 0x19, 0xD2, 0x76, 0x76, 0xC0,
        0x71, 0x62, 0xC8, 0xB5, 0xCC, 0xDE, 0x06, 0x68,
        0x96, 0x1D, 0xF8, 0x68, 0x03, 0x48, 0x2C, 0xB3,
        0x7E, 0xD6, 0xD5, 0xC0, 0xBB, 0x8D, 0x50, 0xCF,
        0x1F, 0x50, 0xD4, 0x76, 0xAA, 0x04, 0x58, 0xBD,
        0xAB, 0xA8, 0x06, 0xF4, 0x8B, 0xE9, 0xDC, 0xB8
    };

    bool passed = false;
    void *ctx = NULL;

    uint8_t discarded[sizeof(expected)] = {0};
    uint8_t returned_bits[sizeof(expected)] = {0};

    if (HMACDRBG.context_size == 0 ||
        HMACDRBG.instantiate == NULL ||
        HMACDRBG.generate == NULL ||
        HMACDRBG.uninstantiate == NULL)
    {
        fprintf(stderr, "    incomplete HMACDRBG descriptor\n");
        return false;
    }

    ctx = calloc(1, HMACDRBG.context_size);

    if (ctx == NULL)
    {
        fprintf(stderr, "    failed to allocate HMAC_DRBG context\n");
        return false;
    }

    DRBGStatus status =
        HMACDRBG.instantiate(
            ctx,
            entropy_input,
            sizeof(entropy_input),
            nonce,
            sizeof(nonce),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    NIST instantiate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    status =
        HMACDRBG.generate(
            ctx,
            discarded,
            sizeof(discarded),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    first NIST generate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    status =
        HMACDRBG.generate(
            ctx,
            returned_bits,
            sizeof(returned_bits),
            NULL,
            0);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    second NIST generate returned status %d\n",
            (int)status);

        goto cleanup;
    }

    passed =
        expect_bytes(
            "NIST HMAC_DRBG basic KAT",
            returned_bits,
            expected,
            sizeof(expected));

cleanup:

    HMACDRBG.uninstantiate(ctx);

    clear_output(discarded, sizeof(discarded));
    clear_output(returned_bits, sizeof(returned_bits));

    free(ctx);
    return passed;
}