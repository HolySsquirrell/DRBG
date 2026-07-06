#include "benchmark.h"

#include "drbg.h"
#include "logger.h"
#include "timer.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

int benchmark_run(
    const DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result)
{
    if (drbg == NULL || config == NULL || result == NULL)
    {
        log_error("Invalid benchmark arguments.");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    void *ctx = NULL;
    uint8_t *buffer = NULL;

    Timer timer;

    ctx = malloc(drbg->context_size);

    if (ctx == NULL)
    {
        log_error("Failed to allocate DRBG context.");
        return -1;
    }

    buffer = malloc(config->output_size);

    if (buffer == NULL)
    {
        log_error("Failed to allocate output buffer.");
        free(ctx);
        return -1;
    }

    memset(ctx, 0, drbg->context_size);
        timer_start(&timer);

    drbg->instantiate(
        ctx,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);

    timer_stop(&timer);

    result->instantiate_time_ms =
        timer_elapsed_milliseconds(&timer);
    
        timer_start(&timer);

    drbg->generate(
        ctx,
        buffer,
        config->output_size,
        NULL,
        0);

    timer_stop(&timer);

    result->generate_time_ms =
        timer_elapsed_milliseconds(&timer);
    
    result->reseed_time_ms = 0.0;

        timer_start(&timer);

    drbg->uninstantiate(ctx);

    timer_stop(&timer);

    result->cleanup_time_ms =
        timer_elapsed_milliseconds(&timer);
    
        result->total_time_ms =
        result->instantiate_time_ms +
        result->generate_time_ms +
        result->cleanup_time_ms;
    
    result->throughput_MBps =
        bytes_to_megabytes(config->output_size) /
        (result->generate_time_ms / 1000.0);
    
    if (config->save_output)
    {
        write_binary_file(
            "output/dummy.bin",
            buffer,
            config->output_size);
    }

    log_info("----------------------------------------");
    log_info("Generator        : %s", drbg->name);
    log_info("Output Size      : %.2f MB",
             bytes_to_megabytes(config->output_size));
    log_info("Instantiate      : %.3f ms",
             result->instantiate_time_ms);
    log_info("Generate         : %.3f ms",
             result->generate_time_ms);
    log_info("Cleanup          : %.3f ms",
             result->cleanup_time_ms);
    log_info("Throughput       : %.2f MB/s",
             result->throughput_MBps);
    log_info("----------------------------------------");
    free(buffer);
    free(ctx);

    return 0;
}