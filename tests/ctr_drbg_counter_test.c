#include "ctr_drbg_counter.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool expect_counter(
    const char *case_name,
    const uint8_t actual[CTR_DRBG_BLOCK_BYTES],
    const uint8_t expected[CTR_DRBG_BLOCK_BYTES])
{
    if (memcmp(
            actual,
            expected,
            CTR_DRBG_BLOCK_BYTES) == 0)
    {
        return true;
    }

    fprintf(
        stderr,
        "    counter mismatch: %s\n",
        case_name);

    return false;
}

bool test_ctr_drbg_counter(void)
{
    {
        uint8_t counter[CTR_DRBG_BLOCK_BYTES] = {0};

        uint8_t expected[CTR_DRBG_BLOCK_BYTES] = {0};
        expected[CTR_DRBG_BLOCK_BYTES - 1] = 1;

        ctr_drbg_increment(counter);

        if (!expect_counter(
                "increment zero",
                counter,
                expected))
        {
            return false;
        }
    }

    {
        uint8_t counter[CTR_DRBG_BLOCK_BYTES] = {0};
        counter[CTR_DRBG_BLOCK_BYTES - 1] = 0xFF;

        uint8_t expected[CTR_DRBG_BLOCK_BYTES] = {0};
        expected[CTR_DRBG_BLOCK_BYTES - 2] = 1;

        ctr_drbg_increment(counter);

        if (!expect_counter(
                "carry",
                counter,
                expected))
        {
            return false;
        }
    }

    {
        uint8_t counter[CTR_DRBG_BLOCK_BYTES];

        memset(
            counter,
            0xFF,
            sizeof(counter));

        uint8_t expected[CTR_DRBG_BLOCK_BYTES] = {0};

        ctr_drbg_increment(counter);

        if (!expect_counter(
                "complete overflow",
                counter,
                expected))
        {
            return false;
        }
    }

    return true;
}