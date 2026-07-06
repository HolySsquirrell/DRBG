#ifndef DUMMY_H
#define DUMMY_H

#include "drbg.h"

#include <stdint.h>

typedef struct
{
    uint8_t counter;
} DummyDRBGContext;

extern const DRBG DummyDRBG;

#endif 