#include "hmac_drbg.h"
#include "hmac_drbg_update.h"
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

bool test_hmac_drbg_update(void)
{
    bool passed = true;

    {
        uint8_t K[HMAC_DRBG_OUTLEN_BYTES] = {0};
        uint8_t V[HMAC_DRBG_OUTLEN_BYTES];

        memset(V, 0x01, sizeof(V));

        static const uint8_t expected_K[HMAC_DRBG_OUTLEN_BYTES] =
        {
            0xA3, 0xE7, 0x77, 0x6D, 0xD1, 0xFC, 0x68, 0x0D,
            0x83, 0xB0, 0x95, 0x51, 0xD2, 0xB1, 0x17, 0x7A,
            0x5C, 0x81, 0x0B, 0xDB, 0xDB, 0x61, 0xB0, 0x23,
            0x90, 0x9C, 0x6F, 0x0A, 0x42, 0xC2, 0xD2, 0x04
        };

        static const uint8_t expected_V[HMAC_DRBG_OUTLEN_BYTES] =
        {
            0xC5, 0x60, 0x9C, 0xE6, 0xCC, 0x1B, 0xAF, 0xD6,
            0x8C, 0x41, 0x0C, 0xB6, 0x72, 0x45, 0xF8, 0x0A,
            0xB4, 0x47, 0x89, 0xC5, 0x1A, 0x9B, 0x30, 0x0B,
            0xDE, 0x0F, 0xB5, 0x9D, 0x1E, 0x15, 0x58, 0x32
        };

        DRBGStatus status =
            hmac_drbg_update(
                K,
                V,
                NULL,
                0);

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "empty-data update K",
                K,
                expected_K,
                sizeof(K)) &&
            expect_bytes(
                "empty-data update V",
                V,
                expected_V,
                sizeof(V)) &&
            passed;
    }

    {
        uint8_t K[HMAC_DRBG_OUTLEN_BYTES] = {0};
        uint8_t V[HMAC_DRBG_OUTLEN_BYTES];
        uint8_t provided_data[48];

        memset(V, 0x01, sizeof(V));

        for (size_t i = 0; i < sizeof(provided_data); ++i)
        {
            provided_data[i] = (uint8_t)i;
        }

        static const uint8_t expected_K[HMAC_DRBG_OUTLEN_BYTES] =
        {
            0x34, 0x5C, 0x7F, 0x09, 0x9D, 0x0C, 0x4A, 0xDC,
            0xE9, 0x13, 0x79, 0xB6, 0xE2, 0xE0, 0x3E, 0xDF,
            0xD4, 0xC2, 0xFA, 0x0B, 0x87, 0x4E, 0x7A, 0x5B,
            0x3C, 0xF2, 0x4F, 0xB1, 0x1F, 0x6E, 0xD4, 0xF1
        };

        static const uint8_t expected_V[HMAC_DRBG_OUTLEN_BYTES] =
        {
            0x97, 0x6B, 0x48, 0x36, 0xA5, 0xB3, 0xD8, 0x28,
            0x29, 0x3E, 0x26, 0x90, 0x03, 0x71, 0xF2, 0xD4,
            0x9E, 0x5A, 0x11, 0x75, 0x4C, 0x0A, 0x45, 0xC9,
            0xCC, 0x4C, 0x8F, 0xE9, 0x21, 0x01, 0x4A, 0x03
        };

        DRBGStatus status =
            hmac_drbg_update(
                K,
                V,
                provided_data,
                sizeof(provided_data));

        passed =
            status == DRBG_STATUS_SUCCESS &&
            expect_bytes(
                "provided-data update K",
                K,
                expected_K,
                sizeof(K)) &&
            expect_bytes(
                "provided-data update V",
                V,
                expected_V,
                sizeof(V)) &&
            passed;
    }

    {
        uint8_t K[HMAC_DRBG_OUTLEN_BYTES] = {0};
        uint8_t V[HMAC_DRBG_OUTLEN_BYTES];

        uint8_t original_K[HMAC_DRBG_OUTLEN_BYTES];
        uint8_t original_V[HMAC_DRBG_OUTLEN_BYTES];

        memset(V, 0x01, sizeof(V));

        memcpy(original_K, K, sizeof(K));
        memcpy(original_V, V, sizeof(V));

        DRBGStatus status =
            hmac_drbg_update(
                K,
                V,
                NULL,
                1);

        if (status != DRBG_STATUS_INVALID_ARGUMENT)
        {
            fprintf(
                stderr,
                "    invalid update returned status %d\n",
                (int)status);

            passed = false;
        }

        passed =
            expect_bytes(
                "invalid update preserves K",
                K,
                original_K,
                sizeof(K)) &&
            expect_bytes(
                "invalid update preserves V",
                V,
                original_V,
                sizeof(V)) &&
            passed;
    }

    return passed;
}