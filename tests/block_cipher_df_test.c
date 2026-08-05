#include "block_cipher_df.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool test_block_cipher_df(void)
{
    uint8_t input[CTR_DRBG_SEED_BYTES];
    uint8_t output[CTR_DRBG_SEED_BYTES] = {0};

    static const uint8_t expected[CTR_DRBG_SEED_BYTES] =
    {
        0xC5, 0xAB, 0x6D, 0x2A,
        0xA7, 0xA4, 0xF2, 0x6B,
        0x87, 0x80, 0xE2, 0x61,
        0x47, 0x06, 0x7B, 0x44,

        0xF9, 0x11, 0xBA, 0x01,
        0xA9, 0xDF, 0x75, 0xB2,
        0xDD, 0xFE, 0x79, 0x54,
        0xA9, 0x07, 0x15, 0xB3,

        0x25, 0x2D, 0x8F, 0x59,
        0xA5, 0xA5, 0x36, 0xC8,
        0xBA, 0x26, 0x27, 0x07,
        0x0D, 0x9E, 0xA7, 0xE0
    };

    for (size_t i = 0; i < sizeof(input); ++i)
    {
        input[i] = (uint8_t)i;
    }

    const DRBGStatus status =
        block_cipher_df(
            input,
            sizeof(input),
            output);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    block_cipher_df returned status %d\n",
            (int)status);

        return false;
    }

    if (memcmp(
            output,
            expected,
            sizeof(expected)) != 0)
    {
        fprintf(
            stderr,
            "    block_cipher_df output mismatch\n");

        for (size_t i = 0; i < sizeof(expected); ++i)
        {
            if (output[i] != expected[i])
            {
                fprintf(
                    stderr,
                    "    byte %zu: got %02X, expected %02X\n",
                    i,
                    output[i],
                    expected[i]);

                break;
            }
        }

        return false;
    }

    return true;
}