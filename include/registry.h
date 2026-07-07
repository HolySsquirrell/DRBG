#ifndef REGISTRY_H
#define REGISTRY_H

#include "drbg.h"

#include <stddef.h>

typedef struct
{
    const char *name;
    const DRBG *drbg;

} DRBGEntry;

const DRBG *drbg_find(const char *name);

size_t registry_count(void);

const DRBGEntry *registry_entries(void);

#endif