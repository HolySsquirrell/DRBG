#include "ctr_drbg_counter.h"

#include <stddef.h>
#include <stdint.h>

void ctr_drbg_increment(
    uint8_t counter[CTR_DRBG_BLOCK_BYTES])
{
    if (counter == NULL)
    {
        return;
    }

    for (size_t i = CTR_DRBG_BLOCK_BYTES; i > 0; --i)
    {
        const size_t index = i - 1;

        counter[index]++;

        if (counter[index] != 0)
        {
            break;
        }
    }
}