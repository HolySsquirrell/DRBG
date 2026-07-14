#include "drbg.h"
#include "hash_drbg.h"
#include "status.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * NIST SP 800-90A Hash_DRBG SHA-256 Known Answer Test
 *
 * Configuration:
 *   PredictionResistance = False
 *   EntropyInputLen       = 256 bits
 *   NonceLen              = 128 bits
 *   PersonalizationLen    = 0 bits
 *   AdditionalInputLen    = 0 bits
 *   ReturnedBitsLen       = 1024 bits
 *
 * Procedure:
 *   1. Instantiate using EntropyInput and Nonce.
 *   2. Generate 1024 bits and discard them.
 *   3. Generate another 1024 bits.
 *   4. Compare the second result with ReturnedBits.
 *
 * The vector originates from the NIST CAVP DRBG test-vector package.
 */

static bool nist_expect_bytes(
    const uint8_t *actual,
    const uint8_t *expected,
    size_t length)
{
    if (memcmp(actual, expected, length) == 0)
    {
        return true;
    }

    fprintf(stderr, "    NIST Hash_DRBG output mismatch\n");

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

bool test_hash_drbg_nist_kat(void)
{
    /*
     * The original NIST vector supplies 384 bits of instantiate
     * entropy material. It is split according to the configuration:
     *
     *   first 256 bits -> EntropyInput
     *   final 128 bits -> Nonce
     */
    static const uint8_t entropy_input[32] =
    {
        0xA6, 0x5A, 0xD0, 0xF3, 0x45, 0xDB, 0x4E, 0x0E,
        0xFF, 0xE8, 0x75, 0xC3, 0xA2, 0xE7, 0x1F, 0x42,
        0xC7, 0x12, 0x9D, 0x62, 0x0F, 0xF5, 0xC1, 0x19,
        0xA9, 0xEF, 0x55, 0xF0, 0x51, 0x85, 0xE0, 0xFB
    };

    static const uint8_t nonce[16] =
    {
        0x85, 0x81, 0xF9, 0x31, 0x75, 0x17, 0x27, 0x6E,
        0x06, 0xE9, 0x60, 0x7D, 0xDB, 0xCB, 0xCC, 0x2E
    };

    static const uint8_t expected_returned_bits[128] =
    {
        0xD3, 0xE1, 0x60, 0xC3, 0x5B, 0x99, 0xF3, 0x40,
        0xB2, 0x62, 0x82, 0x64, 0xD1, 0x75, 0x10, 0x60,
        0xE0, 0x04, 0x5D, 0xA3, 0x83, 0xFF, 0x57, 0xA5,
        0x7D, 0x73, 0xA6, 0x73, 0xD2, 0xB8, 0xD8, 0x0D,
        0xAA, 0xF6, 0xA6, 0xC3, 0x5A, 0x91, 0xBB, 0x45,
        0x79, 0xD7, 0x3F, 0xD0, 0xC8, 0xFE, 0xD1, 0x11,
        0xB0, 0x39, 0x13, 0x06, 0x82, 0x8A, 0xDF, 0xED,
        0x52, 0x8F, 0x01, 0x81, 0x21, 0xB3, 0xFE, 0xBD,
        0xC3, 0x43, 0xE7, 0x97, 0xB8, 0x7D, 0xBB, 0x63,
        0xDB, 0x13, 0x33, 0xDE, 0xD9, 0xD1, 0xEC, 0xE1,
        0x77, 0xCF, 0xA6, 0xB7, 0x1F, 0xE8, 0xAB, 0x1D,
        0xA4, 0x66, 0x24, 0xED, 0x64, 0x15, 0xE5, 0x1C,
        0xCD, 0xE2, 0xC7, 0xCA, 0x86, 0xE2, 0x83, 0x99,
        0x0E, 0xEA, 0xEB, 0x91, 0x12, 0x04, 0x15, 0x52,
        0x8B, 0x22, 0x95, 0x91, 0x02, 0x81, 0xB0, 0x2D,
        0xD4, 0x31, 0xF4, 0xC9, 0xF7, 0x04, 0x27, 0xDF
    };

    bool passed = false;
    void *ctx = NULL;

    uint8_t discarded_output[sizeof(expected_returned_bits)] = {0};
    uint8_t returned_bits[sizeof(expected_returned_bits)] = {0};

    if (HashDRBG.context_size == 0 ||
        HashDRBG.instantiate == NULL ||
        HashDRBG.generate == NULL ||
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

    /*
     * The validation procedure performs the first generate operation
     * only to advance the internal state.
     */
    status =
        HashDRBG.generate(
            ctx,
            discarded_output,
            sizeof(discarded_output),
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
        HashDRBG.generate(
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
        nist_expect_bytes(
            returned_bits,
            expected_returned_bits,
            sizeof(expected_returned_bits));

cleanup:

    HashDRBG.uninstantiate(ctx);

    memset(
        discarded_output,
        0,
        sizeof(discarded_output));

    memset(
        returned_bits,
        0,
        sizeof(returned_bits));

    free(ctx);

    return passed;
}