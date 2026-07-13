#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef KB
#define KB(x) ((size_t)(x) * 1024ULL)
#endif

#ifndef MB
#define MB(x) (KB(x) * 1024ULL)
#endif

#ifndef GB
#define GB(x) (MB(x) * 1024ULL)
#endif

double bytes_to_megabytes(size_t bytes);

void hex_dump(
    const uint8_t *data,
    size_t length);

void secure_zero(
    void *memory,
    size_t length);

bool write_binary_file(
    const char *filename,
    const uint8_t *data,
    size_t length);

#endif