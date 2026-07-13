#ifndef HASH_DF_H
#define HASH_DF_H

#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus hash_df(
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_length);

#endif