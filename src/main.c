#include "logger.h"
#include "timer.h"
#include "utils.h"

int main(void)
{
    Timer timer;

    timer_start(&timer);

    for (volatile int i = 0; i < 100000000; ++i)
    {
        /* Busy wait */
    }

    timer_stop(&timer);

    log_success("Timer test completed.");
    log_info("Elapsed time: %.3f ms", timer_elapsed_milliseconds(&timer));

    return 0;
}