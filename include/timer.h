#ifndef TIMER_H
#define TIMER_H

#include <time.h>

typedef struct
{
    struct timespec start;
    struct timespec end;
} Timer;

void timer_start(Timer *timer);

void timer_stop(Timer *timer);

double timer_elapsed_seconds(const Timer *timer);

double timer_elapsed_milliseconds(const Timer *timer);

#endif