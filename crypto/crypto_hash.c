#include "crypto_hash.h"
#include "status.h"
#include <openssl/evp.h>

DRBGStatus crypto_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[SHA256_DIGEST_SIZE])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return DRBG_STATUS_MEMORY_ERROR;

    int ok = 1;

    ok &= EVP_DigestInit_ex(
            ctx,
            EVP_sha256(),
            NULL);

    ok &= EVP_DigestUpdate(
            ctx,
            input,
            input_length);

    ok &= EVP_DigestFinal_ex(
            ctx,
            output,
            NULL);

    EVP_MD_CTX_free(ctx);

    return ok
        ? DRBG_STATUS_SUCCESS
        : DRBG_STATUS_INTERNAL_ERROR;
}