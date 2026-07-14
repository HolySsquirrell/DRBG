#include "hash_df.h"

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

bool test_hash_df(void)
{
    uint8_t input[32];

    for (size_t i = 0; i < sizeof(input); ++i)
    {
        input[i] = (uint8_t)i;
    }

    /*
     * Regression vector:
     *   input  = 00 01 02 ... 1F
     *   output = 440 bits using SHA-256 Hash_df
     */
    static const uint8_t expected[55] =
    {
        0xF9, 0x6D, 0x96, 0x07, 0xB7, 0x27, 0xDE, 0xAF,
        0x70, 0x7B, 0xE6, 0xE9, 0x79, 0x11, 0x2E, 0x1C,
        0xE6, 0x8D, 0xD9, 0x9A, 0xF2, 0xDA, 0x1D, 0x7A,
        0x9A, 0xE5, 0xCD, 0x1B, 0x55, 0xD7, 0xB6, 0xEA,
        0xCF, 0xE2, 0x21, 0x1D, 0xC6, 0xC3, 0xCE, 0x79,
        0x45, 0x31, 0x94, 0x3E, 0x07, 0x66, 0xB3, 0x93,
        0xBC, 0xAE, 0x5A, 0xE5, 0x6E, 0xBA, 0x99
    };

    uint8_t output[sizeof(expected)] = {0};
    uint8_t second_output[sizeof(expected)] = {0};

    DRBGStatus status =
        hash_df(
            input,
            sizeof(input),
            output,
            sizeof(output));

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    hash_df returned status %d\n",
            (int)status);

        return false;
    }

    if (!expect_bytes(
            "Hash_df regression vector",
            output,
            expected,
            sizeof(expected)))
    {
        return false;
    }

    status =
        hash_df(
            input,
            sizeof(input),
            second_output,
            sizeof(second_output));

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    second hash_df call returned status %d\n",
            (int)status);

        return false;
    }

    if (!expect_bytes(
            "Hash_df determinism",
            second_output,
            output,
            sizeof(output)))
    {
        return false;
    }

    return true;
}