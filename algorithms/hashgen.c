#include "hashgen.h"
#include "crypto_hash.h"
#include "hash_math.h"
#include <string.h>

static void hashgen_secure_zero(
    void *memory,
    size_t length)
{
    volatile uint8_t *bytes =
        (volatile uint8_t *)memory;

    while (length > 0)
    {
        *bytes = 0;

        ++bytes;
        --length;
    }
}

DRBGStatus hashgen(
    const uint8_t V[HASH_DRBG_SEEDLEN_BYTES],
    uint8_t *output,
    size_t output_length)
{
    if (V == NULL || output == NULL || output_length == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    DRBGStatus status = DRBG_STATUS_SUCCESS;

    uint8_t data[HASH_DRBG_SEEDLEN_BYTES];
    uint8_t digest[SHA256_DIGEST_SIZE];

    size_t produced = 0;

    memcpy(
        data,
        V,
        sizeof(data));

    while (produced < output_length)
    {
        status = crypto_sha256(
            data,
            sizeof(data),
            digest);

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        size_t remaining =
            output_length - produced;

        size_t copy_length =
            remaining < SHA256_DIGEST_SIZE
                ? remaining
                : SHA256_DIGEST_SIZE;

        memcpy(
            output + produced,
            digest,
            copy_length);

        produced += copy_length;

        status = hash_math_increment(
            data,
            sizeof(data));

        if (status != DRBG_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

cleanup:

    hashgen_secure_zero(
        digest,
        sizeof(digest));

    hashgen_secure_zero(
        data,
        sizeof(data));

    return status;
}