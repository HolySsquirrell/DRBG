#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

#define BYTES_TO_BITS(x) ((x) * 8ULL)
#define KB(x) ((size_t)(x) * 1024ULL)
#define MB(x) (KB(x) * 1024ULL)
#define GB(x) (MB(x) * 1024ULL)


double bytes_to_megabytes(size_t bytes);

void hex_dump(
    const uint8_t *data,
    size_t length);

int write_binary_file(
    const char *filename,
    const uint8_t *data,
    size_t length);

#endif