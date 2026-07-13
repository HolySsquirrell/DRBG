#include "benchmark.h"
#include "config.h"
#include "csv.h"
#include "entropy.h"
#include "drbg.h"
#include "logger.h"
#include "status.h"
#include "timer.h"
#include "utils.h"
#include <float.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BENCHMARK_RESEED_ENTROPY_BYTES 32U

static DRBGStatus benchmark_reseed(
    const DRBG *drbg,
    void *ctx,
    BenchmarkResult *result);

DRBGStatus benchmark_run(
    const DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result)
{
    DRBGStatus status = DRBG_STATUS_SUCCESS;

    void *ctx = NULL;
    uint8_t *buffer = NULL;

    bool instantiated = false;

    Timer timer;

    uint8_t entropy[32] = {0};
    uint8_t nonce[16] = {0};

    EntropySeedMaterial seed =
    {
        .entropy = entropy,
        .entropy_length = sizeof(entropy),

        .nonce = nonce,
        .nonce_length = sizeof(nonce)
    };

    double total_generate_time_ms = 0.0;
    size_t requests_since_reseed = 0;

    if (drbg == NULL ||
        config == NULL ||
        result == NULL)
    {
        log_error("Invalid benchmark arguments.");
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (config->output_size == 0 ||
        config->repetitions == 0 ||
        drbg->context_size == 0 ||
        drbg->instantiate == NULL ||
        drbg->generate == NULL ||
        drbg->uninstantiate == NULL)
    {
        log_error(
            "Invalid benchmark configuration or DRBG interface.");

        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (config->reseed_interval > 0 &&
        drbg->reseed == NULL)
    {
        log_error(
            "Reseeding is not available for %s.",
            drbg->name);

        return DRBG_STATUS_NOT_IMPLEMENTED;
    }

    memset(result, 0, sizeof(*result));

    result->min_generate_time_ms = DBL_MAX;
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

    status = entropy_get_seed_material(&seed);

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error(
            "Failed to acquire seed material with status %d.",
            (int)status);

        goto cleanup;
    }

    timer_start(&timer);

    status = drbg->instantiate(
        ctx,
        seed.entropy,
        seed.entropy_length,
        seed.nonce,
        seed.nonce_length,
        NULL,
        0);

    timer_stop(&timer);

    secure_zero(entropy, sizeof(entropy));
    secure_zero(nonce, sizeof(nonce));

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error(
            "DRBG instantiation failed with status %d.",
            (int)status);

        goto cleanup;
    }

    instantiated = true;

    result->instantiate_time_ms =
        timer_elapsed_milliseconds(&timer);

    for (size_t repetition = 0;
         repetition < config->repetitions;
         ++repetition)
    {
        size_t produced = 0;
        double repetition_generate_time_ms = 0.0;

        while (produced < config->output_size)
        {
            if (config->reseed_interval > 0 &&
                requests_since_reseed >=
                    config->reseed_interval)
            {
                status = benchmark_reseed(
                    drbg,
                    ctx,
                    result);

                if (status != DRBG_STATUS_SUCCESS)
                {
                    log_error(
                        "DRBG reseed failed before repetition %zu "
                        "at byte offset %zu with status %d.",
                        repetition + 1,
                        produced,
                        (int)status);

                    goto cleanup;
                }

                requests_since_reseed = 0;
            }

            size_t remaining =
                config->output_size - produced;

            size_t request_size = remaining;

            if (drbg->max_request_size > 0 &&
                request_size > drbg->max_request_size)
            {
                request_size =
                    drbg->max_request_size;
            }

            timer_start(&timer);

            status = drbg->generate(
                ctx,
                buffer + produced,
                request_size,
                NULL,
                0);

            timer_stop(&timer);

            if (status != DRBG_STATUS_SUCCESS)
            {
                log_error(
                    "DRBG generation failed during repetition %zu "
                    "after %zu bytes with status %d.",
                    repetition + 1,
                    produced,
                    (int)status);

                goto cleanup;
            }

            repetition_generate_time_ms +=
                timer_elapsed_milliseconds(&timer);

            produced += request_size;

            result->generate_request_count++;
            requests_since_reseed++;
        }

        if (config->verify_output)
        {
            if (drbg->verify == NULL)
            {
                log_error(
                    "Output verification is not available for %s.",
                    drbg->name);

                status = DRBG_STATUS_NOT_IMPLEMENTED;
                goto cleanup;
            }

            status = drbg->verify(
                ctx,
                buffer,
                config->output_size);

            if (status != DRBG_STATUS_SUCCESS)
            {
                log_error(
                    "Output verification failed for %s "
                    "with status %d.",
                    drbg->name,
                    (int)status);

                goto cleanup;
            }
        }

        total_generate_time_ms +=
            repetition_generate_time_ms;

        if (repetition_generate_time_ms <
            result->min_generate_time_ms)
        {
            result->min_generate_time_ms =
                repetition_generate_time_ms;
        }

        if (repetition_generate_time_ms >
            result->max_generate_time_ms)
        {
            result->max_generate_time_ms =
                repetition_generate_time_ms;
        }
    }

    result->average_generate_time_ms =
        total_generate_time_ms /
        (double)config->repetitions;

    result->generate_time_ms =
        result->average_generate_time_ms;

    timer_start(&timer);

    drbg->uninstantiate(ctx);

    timer_stop(&timer);

    instantiated = false;

    result->cleanup_time_ms =
        timer_elapsed_milliseconds(&timer);

    result->total_time_ms =
        result->instantiate_time_ms +
        total_generate_time_ms +
        result->reseed_entropy_time_ms +
        result->reseed_time_ms +
        result->cleanup_time_ms;

    if (total_generate_time_ms <= 0.0)
    {
        log_error(
            "Generation time is too small to calculate throughput.");

        status = DRBG_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    double total_output_MB =
        bytes_to_megabytes(config->output_size) *
        (double)config->repetitions;


    result->throughput_MBps =
        total_output_MB /
        (total_generate_time_ms / 1000.0);

    double effective_time_ms =
        total_generate_time_ms +
        result->reseed_entropy_time_ms +
        result->reseed_time_ms;

    if (effective_time_ms > 0.0)
    {
        result->effective_throughput_MBps =
            total_output_MB /
            (effective_time_ms / 1000.0);
    }

    if (config->save_output)
    {
        if (!write_binary_file(
                "output/drbg.bin",
                buffer,
                config->output_size))
        {
            log_error("Failed to save output file.");

            status = DRBG_STATUS_FILE_ERROR;
            goto cleanup;
        }
    }

    log_info("========================================");
    log_info("Generator         : %s", drbg->name);
    log_info(
        "Output Size       : %.2f MB",
        bytes_to_megabytes(config->output_size));
    log_info(
        "Repetitions       : %zu",
        config->repetitions);
    log_info(
        "Generate Requests : %zu",
        result->generate_request_count);
    log_info(
        "Reseed Interval   : %zu",
        config->reseed_interval);
    log_info(
        "Reseed Count      : %zu",
        result->reseed_count);

    log_info("");

    log_info(
        "Instantiate       : %.3f ms",
        result->instantiate_time_ms);
    log_info(
        "Generate Avg      : %.3f ms",
        result->average_generate_time_ms);
    log_info(
        "Generate Min      : %.3f ms",
        result->min_generate_time_ms);
    log_info(
        "Generate Max      : %.3f ms",
        result->max_generate_time_ms);
    log_info(
        "Reseed Entropy    : %.3f ms",
        result->reseed_entropy_time_ms);
    log_info(
        "Reseed Algorithm  : %.3f ms",
        result->reseed_time_ms);
    log_info(
        "Cleanup           : %.3f ms",
        result->cleanup_time_ms);
    log_info(
        "Total Measured    : %.3f ms",
        result->total_time_ms);

    log_info("");

    log_info(
        "Throughput        : %.2f MB/s",
        result->throughput_MBps);
    log_info(
        "Effective         : %.2f MB/s",
        result->effective_throughput_MBps);

    log_info("========================================");

    if (!csv_append_result(
            RESULTS_CSV_FILE,
            drbg->name,
            config,
            result))
    {
        log_error("Failed to append CSV result.");

        status = DRBG_STATUS_FILE_ERROR;
        goto cleanup;
    }

cleanup:

    if (ctx != NULL)
    {
        if (instantiated &&
            drbg != NULL &&
            drbg->uninstantiate != NULL)
        {
            drbg->uninstantiate(ctx);
        }

        if (drbg != NULL)
        {
            secure_zero(
                ctx,
                drbg->context_size);
        }
    }

    secure_zero(entropy, sizeof(entropy));
    secure_zero(nonce, sizeof(nonce));

    if (buffer != NULL)
    {
        secure_zero(
            buffer,
            config->output_size);
    }

    free(buffer);
    free(ctx);

    return status;
}

static DRBGStatus benchmark_reseed(
    const DRBG *drbg,
    void *ctx,
    BenchmarkResult *result)
{
    if (drbg == NULL ||
        ctx == NULL ||
        result == NULL)
    {
        return DRBG_STATUS_INVALID_ARGUMENT;
    }

    if (drbg->reseed == NULL)
    {
        return DRBG_STATUS_NOT_IMPLEMENTED;
    }

    uint8_t entropy[
        BENCHMARK_RESEED_ENTROPY_BYTES] = {0};

    Timer timer;
    DRBGStatus status;

    timer_start(&timer);

    status = entropy_get(
        entropy,
        sizeof(entropy));

    timer_stop(&timer);

    result->reseed_entropy_time_ms +=
        timer_elapsed_milliseconds(&timer);

    if (status != DRBG_STATUS_SUCCESS)
    {
        secure_zero(
            entropy,
            sizeof(entropy));

        return status;
    }
    timer_start(&timer);

    status = drbg->reseed(
        ctx,
        entropy,
        sizeof(entropy),
        NULL,
        0);

    timer_stop(&timer);

    result->reseed_time_ms +=
        timer_elapsed_milliseconds(&timer);

    secure_zero(
        entropy,
        sizeof(entropy));

    if (status != DRBG_STATUS_SUCCESS)
    {
        return status;
    }

    result->reseed_count++;

    return DRBG_STATUS_SUCCESS;
}