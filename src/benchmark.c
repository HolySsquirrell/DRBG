#include "benchmark.h"

#include "drbg.h"
#include "logger.h"
#include "status.h"
#include "timer.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

DRBGStatus benchmark_run(
    const DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    void *ctx = NULL;
    uint8_t *buffer = NULL;
    Timer timer;

    double total_generate_time = 0.0;

    if (drbg == NULL || config == NULL || result == NULL)
    {
        log_error("Invalid benchmark arguments.");
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    memset(result, 0, sizeof(*result));

    result->min_generate_time_ms = 1e30;
    result->max_generate_time_ms = 0.0;

    ctx = malloc(drbg->context_size);

    if (ctx == NULL)
    {
        log_error("Failed to allocate DRBG context.");
        status = DRBG_STATUS_MEMORY_ERROR;
        goto cleanup;
    }

    memset(ctx, 0, drbg->context_size);

    buffer = malloc(config->output_size);

    if (buffer == NULL)
    {
        log_error("Failed to allocate output buffer.");
        status = DRBG_STATUS_MEMORY_ERROR;
        goto cleanup;
    }

    timer_start(&timer);

    status = drbg->instantiate(
        ctx,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);

    timer_stop(&timer);

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error("DRBG instantiation failed.");
        goto cleanup;
    }

    result->instantiate_time_ms =
        timer_elapsed_milliseconds(&timer);

    for (size_t i = 0; i < config->repetitions; ++i)
    {
        timer_start(&timer);

        status = drbg->generate(
            ctx,
            buffer,
            config->output_size,
            NULL,
            0);

        timer_stop(&timer);

        if (status != DRBG_STATUS_SUCCESS)
        {
            log_error("DRBG generation failed.");
            goto cleanup;
        }

        double elapsed =
            timer_elapsed_milliseconds(&timer);

        total_generate_time += elapsed;

        if (elapsed < result->min_generate_time_ms)
            result->min_generate_time_ms = elapsed;

        if (elapsed > result->max_generate_time_ms)
            result->max_generate_time_ms = elapsed;
    }

    result->average_generate_time_ms =
        total_generate_time / config->repetitions;

    result->generate_time_ms =
        result->average_generate_time_ms;


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
        (result->average_generate_time_ms / 1000.0);

    if (config->save_output)
    {
        if (!write_binary_file(
                "output/dummy.bin",
                buffer,
                config->output_size))
        {
            log_error("Failed to save output file.");
            status = DRBG_STATUS_FILE_ERROR;
            goto cleanup;
        }
    }

    log_info("========================================");
    log_info("Generator        : %s", drbg->name);
    log_info("Output Size      : %.2f MB",
             bytes_to_megabytes(config->output_size));
    log_info("Repetitions      : %zu",
             config->repetitions);

    log_info("");

    log_info("Instantiate      : %.3f ms",
             result->instantiate_time_ms);

    log_info("Generate Avg     : %.3f ms",
             result->average_generate_time_ms);

    log_info("Generate Min     : %.3f ms",
             result->min_generate_time_ms);

    log_info("Generate Max     : %.3f ms",
             result->max_generate_time_ms);

    log_info("Cleanup          : %.3f ms",
             result->cleanup_time_ms);

    log_info("");

    log_info("Throughput       : %.2f MB/s",
             result->throughput_MBps);

    log_info("========================================");

cleanup:

    free(buffer);
    free(ctx);

    return status;
}