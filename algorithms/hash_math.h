#ifndef HASH_MATH_H
#define HASH_MATH_H

#include "status.h"

#include <stddef.h>
#include <stdint.h>

DRBGStatus hash_math_increment(
    uint8_t *value,
    size_t value_length);


DRBGStatus hash_math_add_bytes(
    uint8_t *value,
    size_t value_length,
    const uint8_t *addend,
    size_t addend_length);


DRBGStatus hash_math_add_u64(
    uint8_t *value,
    size_t value_length,
    uint64_t addend);

#endif 