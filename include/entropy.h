#ifndef ENTROPY_H
#define ENTROPY_H

#include "status.h"

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint8_t *entropy;
    size_t entropy_length;

    uint8_t *nonce;
    size_t nonce_length;

} EntropySeedMaterial;

DRBGStatus entropy_initialize(void);

DRBGStatus entropy_get(
    uint8_t *buffer,
    size_t length);

DRBGStatus entropy_get_seed_material(
    EntropySeedMaterial *seed);

DRBGStatus entropy_shutdown(void);

#endif