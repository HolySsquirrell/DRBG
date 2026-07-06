#include "timer.h"

void timer_start(Timer *timer)
{
    timespec_get(&timer->start, TIME_UTC);
}

void timer_stop(Timer *timer)
{
    timespec_get(&timer->end, TIME_UTC);
}

double timer_elapsed_seconds(const Timer *timer)
{
    time_t sec = timer->end.tv_sec - timer->start.tv_sec;
    long nsec = timer->end.tv_nsec - timer->start.tv_nsec;

    return (double)sec + (double)nsec / 1e9;
}

double timer_elapsed_milliseconds(const Timer *timer)
{
    return timer_elapsed_seconds(timer) * 1000.0;
}