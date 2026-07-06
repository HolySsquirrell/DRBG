#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

double bytes_to_megabytes(size_t bytes);

void hex_dump(
    const uint8_t *data,
    size_t length);

int write_binary_file(
    const char *filename,
    const uint8_t *data,
    size_t length);

#endif