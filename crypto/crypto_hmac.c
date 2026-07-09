#include "crypto_hmac.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>

DRBGStatus crypto_hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t output[HMAC_SHA256_DIGEST_SIZE])
{
    DRBGStatus status = DRBG_STATUS_INTERNAL_ERROR;

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;

    OSSL_PARAM params[2];

    size_t out_len = 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);

    if (mac == NULL)
        return DRBG_STATUS_INTERNAL_ERROR;

    ctx = EVP_MAC_CTX_new(mac);

    if (ctx == NULL)
        goto cleanup;

    params[0] =
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            "SHA256",
            0);

    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(
            ctx,
            key,
            key_length,
            params))
        goto cleanup;

    if (!EVP_MAC_update(
            ctx,
            input,
            input_length))
        goto cleanup;

    if (!EVP_MAC_final(
            ctx,
            output,
            &out_len,
            HMAC_SHA256_DIGEST_SIZE))
        goto cleanup;

    status = DRBG_STATUS_SUCCESS;

cleanup:

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return status;
}