#include "dummy.h"

#include <stddef.h>
#include <stdint.h>

static DRBGStatus dummy_instantiate(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *personalization,
    size_t personalization_len)
{
    (void)entropy;
    (void)entropy_len;
    (void)nonce;
    (void)nonce_len;
    (void)personalization;
    (void)personalization_len;

    DummyDRBGContext *context = (DummyDRBGContext *)ctx;

    context->counter = 0;

    return DRBG_STATUS_SUCCESS;
}

static DRBGStatus dummy_generate(
    void *ctx,
    uint8_t *output,
    size_t output_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    (void)additional_input;
    (void)additional_len;

    DummyDRBGContext *context = (DummyDRBGContext *)ctx;

    for (size_t i = 0; i < output_len; ++i)
    {
        output[i] = context->counter++;
    }

    return DRBG_STATUS_SUCCESS;
}

static DRBGStatus dummy_reseed(
    void *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *additional_input,
    size_t additional_len)
{
    (void)entropy;
    (void)entropy_len;
    (void)additional_input;
    (void)additional_len;

    DummyDRBGContext *context = (DummyDRBGContext *)ctx;

    context->counter = 0;

    return DRBG_STATUS_SUCCESS;
}

static DRBGStatus dummy_verify(
    const void *ctx,
    const uint8_t *output,
    size_t length)
{
    (void)ctx;

    for (size_t i = 0; i < length; ++i)
    {
        if (output[i] != (uint8_t)i)
        {
            return DRBG_STATUS_GENERATE_ERROR;
        }
    }

    return DRBG_STATUS_SUCCESS;
}

static void dummy_uninstantiate(void *ctx)
{
    DummyDRBGContext *context = (DummyDRBGContext *)ctx;

    context->counter = 0;
}

const DRBG DummyDRBG =
{
    .name = "Dummy_DRBG",
    
    .max_request_size = 0,

    .context_size = sizeof(DummyDRBGContext),

    .instantiate = dummy_instantiate,

    .generate = dummy_generate,

    .reseed = dummy_reseed,

    .verify = dummy_verify,

    .uninstantiate = dummy_uninstantiate
};