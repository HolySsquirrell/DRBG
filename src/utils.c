#include "utils.h"

#include <stdio.h>

double bytes_to_megabytes(size_t bytes)
{
    return (double)bytes /
           (1024.0 * 1024.0);
}

void hex_dump(
    const uint8_t *data,
    size_t length)
{
    if (data == NULL)
    {
        return;
    }

    for (size_t i = 0; i < length; ++i)
    {
        printf("%02X ", data[i]);

        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }

    if (length % 16 != 0)
    {
        printf("\n");
    }
}

void secure_zero(
    void *memory,
    size_t length)
{
    if (memory == NULL)
    {
        return;
    }

    volatile uint8_t *bytes =
        (volatile uint8_t *)memory;

    while (length > 0)
    {
        *bytes = 0;

        ++bytes;
        --length;
    }
}

bool write_binary_file(
    const char *filename,
    const uint8_t *data,
    size_t length)
{
    if (filename == NULL)
    {
        return false;
    }

    if (length > 0 && data == NULL)
    {
        return false;
    }

    FILE *file =
        fopen(filename, "wb");

    if (file == NULL)
    {
        return false;
    }

    size_t bytes_written =
        fwrite(
            data,
            1,
            length,
            file);

    int close_result =
        fclose(file);

    return bytes_written == length &&
           close_result == 0;
}