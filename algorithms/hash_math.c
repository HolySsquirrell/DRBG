#include "hash_math.h"

DRBGStatus hash_math_increment(
    uint8_t *value,
    size_t value_length)
{
    if (value == NULL || value_length == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    /*
     * value is stored in big-endian order, so addition starts
     * at the final byte, which is the least-significant byte.
     */
    for (size_t i = value_length; i > 0; --i)
    {
        value[i - 1]++;

        /*
         * If the result is non-zero, there was no overflow from
         * this byte, and propagation is complete.
         */
        if (value[i - 1] != 0)
        {
            break;
        }
    }

    /*
     * Any carry beyond the first byte is discarded, implementing
     * arithmetic modulo 2^(value_length * 8).
     */
    return DRBG_STATUS_SUCCESS;
}

DRBGStatus hash_math_add_bytes(
    uint8_t *value,
    size_t value_length,
    const uint8_t *addend,
    size_t addend_length)
{
    if (value == NULL || value_length == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (addend_length > 0 && addend == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (addend_length == 0)
    {
        return DRBG_STATUS_SUCCESS;
    }

    size_t value_index = value_length;
    size_t addend_index = addend_length;

    uint16_t carry = 0;

    /*
     * Both operands are big-endian. Start at their
     * least-significant bytes and propagate carries leftward.
     */
    while (value_index > 0)
    {
        --value_index;

        uint16_t sum =
            (uint16_t)value[value_index] +
            carry;

        if (addend_index > 0)
        {
            --addend_index;
            sum += addend[addend_index];
        }

        value[value_index] = (uint8_t)(sum & 0xFFU);
        carry = (uint16_t)(sum >> 8);
    }

    /*
     * Any remaining high-order addend bytes and final carry are
     * discarded. This gives the required modular result.
     */
    return DRBG_STATUS_SUCCESS;
}

DRBGStatus hash_math_add_u64(
    uint8_t *value,
    size_t value_length,
    uint64_t addend)
{
    if (value == NULL || value_length == 0)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    uint8_t encoded_addend[8];

    /*
     * Encode the integer in big-endian order.
     */
    encoded_addend[0] = (uint8_t)(addend >> 56);
    encoded_addend[1] = (uint8_t)(addend >> 48);
    encoded_addend[2] = (uint8_t)(addend >> 40);
    encoded_addend[3] = (uint8_t)(addend >> 32);
    encoded_addend[4] = (uint8_t)(addend >> 24);
    encoded_addend[5] = (uint8_t)(addend >> 16);
    encoded_addend[6] = (uint8_t)(addend >> 8);
    encoded_addend[7] = (uint8_t)addend;

    return hash_math_add_bytes(
        value,
        value_length,
        encoded_addend,
        sizeof(encoded_addend));
}