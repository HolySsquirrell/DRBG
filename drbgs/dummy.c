#include "dummy.h"

#include <stddef.h>
#include <stdint.h>

static int dummy_instantiate(
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

    return 0;
}

static int dummy_generate(
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

    return 0;
}

static int dummy_reseed(
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

    return 0;
}

static void dummy_uninstantiate(void *ctx)
{
    DummyDRBGContext *context = (DummyDRBGContext *)ctx;

    context->counter = 0;
}

const DRBG DummyDRBG =
{
    .name = "Dummy_DRBG",

    .context_size = sizeof(DummyDRBGContext),

    .instantiate = dummy_instantiate,

    .generate = dummy_generate,

    .reseed = dummy_reseed,

    .uninstantiate = dummy_uninstantiate
};