#include "ctr_drbg_bcc.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool test_ctr_drbg_bcc(void)
{
    uint8_t key[CTR_DRBG_KEY_BYTES];
    uint8_t data[32];

    uint8_t output[CTR_DRBG_BLOCK_BYTES] = {0};

    static const uint8_t expected[CTR_DRBG_BLOCK_BYTES] =
    {
        0xC7, 0x71, 0x47, 0xEB,
        0xD5, 0x12, 0x1D, 0xE8,
        0xD0, 0xFA, 0xE7, 0x76,
        0x24, 0x23, 0xB6, 0xBF
    };

    for (size_t i = 0; i < sizeof(key); ++i)
    {
        key[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < sizeof(data); ++i)
    {
        data[i] = (uint8_t)i;
    }

    const DRBGStatus status =
        ctr_drbg_bcc(
            key,
            data,
            sizeof(data),
            output);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "    BCC returned status %d\n",
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
            "    BCC output mismatch\n");

        return false;
    }

    if (ctr_drbg_bcc(
            key,
            data,
            sizeof(data) - 1U,
            output) !=
        DRBG_STATUS_INVALID_ARGUMENT)
    {
        fprintf(
            stderr,
            "    BCC accepted non-block-aligned input\n");

        return false;
    }

    return true;
}