#include "crypto_aes.h"

#include <openssl/evp.h>

DRBGStatus crypto_aes256_encrypt_block(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t input[AES_BLOCK_SIZE],
    uint8_t output[AES_BLOCK_SIZE])
{
    DRBGStatus status = DRBG_STATUS_INTERNAL_ERROR;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return DRBG_STATUS_MEMORY_ERROR;

    int out_len = 0;

    if (!EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_ecb(),
            NULL,
            key,
            NULL))
        goto cleanup;

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_EncryptUpdate(
            ctx,
            output,
            &out_len,
            input,
            AES_BLOCK_SIZE))
        goto cleanup;

    status = DRBG_STATUS_SUCCESS;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    return status;
}