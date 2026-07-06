#include "utils.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

double bytes_to_megabytes(size_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

void hex_dump(
    const uint8_t *data,
    size_t length)
{
    for(size_t i = 0; i < length; i++)
    {
        printf("%02X ", data[i]);

        if((i + 1) % 16 == 0)
            printf("\n");
    }

    printf("\n");
}

int write_binary_file(
    const char *filename,
    const uint8_t *data,
    size_t length)
{
    FILE *fp = fopen(filename, "wb");

    if(fp == NULL)
        return -1;

    fwrite(data, 1, length, fp);

    fclose(fp);

    return 0;
}