#ifndef DRBG_H
#define DRBG_H

#include "status.h"
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    const char *name;

    size_t context_size;

    DRBGStatus (*instantiate)(
        void *ctx,
        const uint8_t *entropy,
        size_t entropy_len,
        const uint8_t *nonce,
        size_t nonce_len,
        const uint8_t *personalization,
        size_t personalization_len);

    DRBGStatus (*generate)(
        void *ctx,
        uint8_t *output,
        size_t output_len,
        const uint8_t *additional_input,
        size_t additional_len);

    DRBGStatus (*reseed)(
        void *ctx,
        const uint8_t *entropy,
        size_t entropy_len,
        const uint8_t *additional_input,
        size_t additional_len);
        
    DRBGStatus (*verify)(
        const void *context,
        const uint8_t *output,
        size_t output_len);

    void (*uninstantiate)(
        void *ctx);

} DRBG;

#endif