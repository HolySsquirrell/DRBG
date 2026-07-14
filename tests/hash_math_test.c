#include "hash_math.h"

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

bool test_hash_math(void)
{
    bool passed = true;

    {
        uint8_t value[] = {0x00, 0x00, 0x00, 0xFF};
        const uint8_t expected[] = {0x00, 0x00, 0x01, 0x00};

        DRBGStatus status =
            hash_math_increment(value, sizeof(value));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "increment with carry",
                value,
                expected,
                sizeof(value)) &&
            passed;
    }

    {
        uint8_t value[] = {0xFF, 0xFF};
        const uint8_t expected[] = {0x00, 0x00};

        DRBGStatus status =
            hash_math_increment(value, sizeof(value));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "increment modulo wrap",
                value,
                expected,
                sizeof(value)) &&
            passed;
    }

    {
        uint8_t value[] = {0x00, 0x00, 0xFF, 0xFF};
        const uint8_t addend[] = {0x01};
        const uint8_t expected[] = {0x00, 0x01, 0x00, 0x00};

        DRBGStatus status =
            hash_math_add_bytes(
                value,
                sizeof(value),
                addend,
                sizeof(addend));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "add shorter big-endian value",
                value,
                expected,
                sizeof(value)) &&
            passed;
    }

    {
        uint8_t value[] = {0xFF, 0xFF, 0xFF, 0xFE};
        const uint8_t addend[] = {0x00, 0x00, 0x00, 0x02};
        const uint8_t expected[] = {0x00, 0x00, 0x00, 0x00};

        DRBGStatus status =
            hash_math_add_bytes(
                value,
                sizeof(value),
                addend,
                sizeof(addend));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "add bytes modulo wrap",
                value,
                expected,
                sizeof(value)) &&
            passed;
    }

    {
        uint8_t value[10] = {0};
        const uint8_t expected[10] =
        {
            0x00, 0x00,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        };

        DRBGStatus status =
            hash_math_add_u64(
                value,
                sizeof(value),
                UINT64_C(0x0102030405060708));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "add uint64 big-endian",
                value,
                expected,
                sizeof(value)) &&
            passed;
    }

    if (!passed)
    {
        fprintf(stderr, "  hash_math tests failed\n");
    }

    return passed;
}