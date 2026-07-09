#include "entropy.h"
#include "status.h"
#include "logger.h"

#include <windows.h>
#include <bcrypt.h>


DRBGStatus entropy_initialize(void)
{
    log_info("Entropy source initialized.");

    return DRBG_STATUS_SUCCESS;
}

DRBGStatus entropy_get(
    uint8_t *buffer,
    size_t length)
{
    if (buffer == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    NTSTATUS status =
        BCryptGenRandom(
            NULL,
            buffer,
            (ULONG)length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error("BCryptGenRandom failed.");

        return DRBG_STATUS_ENTROPY_ERROR;
    }

    return DRBG_STATUS_SUCCESS;
}

DRBGStatus entropy_get_seed_material(
    EntropySeedMaterial *seed)
{
    if (seed == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (seed->entropy == NULL || seed->nonce == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    DRBGStatus status;

    status = entropy_get(
        seed->entropy,
        seed->entropy_length);

    if (status != DRBG_STATUS_SUCCESS)
    {
        return status;
    }

    status = entropy_get(
        seed->nonce,
        seed->nonce_length);

    return status;
}

DRBGStatus entropy_shutdown(void)
{
    log_info("Entropy source shutdown.");

    return DRBG_STATUS_SUCCESS;
}