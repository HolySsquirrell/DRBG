#include "registry.h"

#include "dummy.h"
#include "hash_drbg.h"
#include "hmac_drbg.h"
#include <string.h>

static const DRBGEntry registry[] =
{
    { "dummy", &DummyDRBG },
    { "hash", &HashDRBG },
    { "hmac",&HMACDRBG}
};

const DRBG *drbg_find(const char *name)
{
    size_t count = registry_count();

    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(name, registry[i].name) == 0)
        {
            return registry[i].drbg;
        }
    }

    return NULL;
}

size_t registry_count(void)
{
    return sizeof(registry) / sizeof(registry[0]);
}

const DRBGEntry *registry_entries(void)
{
    return registry;
}