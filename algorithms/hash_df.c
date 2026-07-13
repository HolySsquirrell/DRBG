#include "hash_df.h"

#include "crypto_hash.h"
#include "status.h"

#include <stdlib.h>
#include <string.h>

static void store_u32_be(
    uint32_t value,
    uint8_t out[4])
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

DRBGStatus hash_df(
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_length)
{
    if (input == NULL || output == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (output_length == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    DRBGStatus status = DRBG_STATUS_SUCCESS;

    const uint32_t requested_bits =
        (uint32_t)(output_length * 8);

    const size_t hash_input_length =
        1 +                    
        4 +                    
        input_length;

    uint8_t *hash_input = malloc(hash_input_length);

    if (hash_input == NULL)
    {
        return DRBG_STATUS_MEMORY_ERROR;
    }

    uint8_t digest[SHA256_DIGEST_SIZE];

    size_t produced = 0;

    uint8_t counter = 1;

    while (produced < output_length)
    {
        hash_input[0] = counter;

        store_u32_be(
            requested_bits,
            &hash_input[1]);

        memcpy(
            &hash_input[5],
            input,
            input_length);

        status = crypto_sha256(
            hash_input,
            hash_input_length,
            digest);

        if (status != DRBG_STATUS_SUCCESS)
        {
            free(hash_input);
            return status;
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

        counter++;
    }

    free(hash_input);

    return DRBG_STATUS_SUCCESS;
}