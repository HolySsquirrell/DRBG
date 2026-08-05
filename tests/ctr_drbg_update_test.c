#include "ctr_drbg.h"
#include "ctr_drbg_update.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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

    fprintf(
        stderr,
        "    mismatch: %s\n",
        name);

    for (size_t i = 0; i < length; ++i)
    {
        if (actual[i] != expected[i])
        {
            fprintf(
                stderr,
                "    byte %zu: got %02X, expected %02X\n",
                i,
                actual[i],
                expected[i]);

            break;
        }
    }

    return false;
}

bool test_ctr_drbg_update(void)
{
    uint8_t key[CTR_DRBG_KEY_BYTES];
    uint8_t v[CTR_DRBG_BLOCK_BYTES];
    uint8_t provided_data[CTR_DRBG_SEED_BYTES];

    static const uint8_t expected_key[CTR_DRBG_KEY_BYTES] =
    {
        0xCA, 0x5E, 0x79, 0x43, 0xF5, 0x2F, 0x32, 0xC6,
        0x66, 0xAE, 0x5F, 0x2A, 0x46, 0x7A, 0x88, 0x81,
        0x89, 0x7D, 0x33, 0x48, 0x00, 0x0D, 0xE3, 0x8F,
        0x60, 0x9C, 0x3A, 0x0B, 0x89, 0x49, 0xEC, 0x90
    };

    static const uint8_t expected_v[CTR_DRBG_BLOCK_BYTES] =
    {
        0x69, 0x49, 0xE1, 0x0E, 0xF2, 0xD5, 0xC1, 0x05,
        0x3B, 0x32, 0xF6, 0xDF, 0xD0, 0x4E, 0x76, 0x8B
    };

    for (size_t i = 0; i < sizeof(key); ++i)
    {
        key[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < sizeof(v); ++i)
    {
        v[i] = (uint8_t)(0xF0U + i);
    }

    for (size_t i = 0;
         i < sizeof(provided_data);
         ++i)
    {
        provided_data[i] = (uint8_t)i;
    }

    const DRBGStatus status =
        ctr_drbg_update(
            key,
            v,
            provided_data);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    ctr_drbg_update returned status %d\n",
            (int)status);

        return false;
    }

    if (!expect_bytes(
            "updated Key",
            key,
            expected_key,
            sizeof(expected_key)))
    {
        return false;
    }

    if (!expect_bytes(
            "updated V",
            v,
            expected_v,
            sizeof(expected_v)))
    {
        return false;
    }

    return true;
}