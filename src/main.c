#include "benchmark.h"
#include "cli.h"
#include "config.h"
#include "csv.h"
#include "drbg.h"
#include "entropy.h"
#include "logger.h"
#include "status.h"

#include <stdbool.h>
#include <stdlib.h>

static const char *status_to_string(DRBGStatus status)
{
    switch (status)
    {
        case DRBG_STATUS_SUCCESS:
            return "success";

        case DRBG_STATUS_INVALID_ARGUMENT:
            return "invalid argument";

        case DRBG_STATUS_MEMORY_ERROR:
            return "memory allocation error";

        case DRBG_STATUS_ENTROPY_ERROR:
            return "entropy source error";

        case DRBG_STATUS_GENERATE_ERROR:
            return "generation error";

        case DRBG_STATUS_FILE_ERROR:
            return "file error";

        case DRBG_STATUS_INTERNAL_ERROR:
            return "internal cryptographic error";

        case DRBG_STATUS_NOT_IMPLEMENTED:
            return "operation not implemented";

        case DRBG_STATUS_RESEED_REQUIRED:
            return "reseed required";

        default:
            return "unknown error";
    }
}

int main(int argc, char *argv[])
{
    BenchmarkConfig config;
    BenchmarkResult result;

    const DRBG *drbg = NULL;

    DRBGStatus status = DRBG_STATUS_SUCCESS;
    bool entropy_initialized = false;

    int exit_code = EXIT_FAILURE;

    if (!cli_parse_arguments(
            argc,
            argv,
            &config,
            &drbg))
    {
        return EXIT_FAILURE;
    }

    if (!csv_write_header(RESULTS_CSV_FILE))
    {
        log_error("Failed to initialize CSV results file.");
        return EXIT_FAILURE;
    }

    status = entropy_initialize();

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error(
            "Entropy initialization failed: %s.",
            status_to_string(status));

        return EXIT_FAILURE;
    }

    entropy_initialized = true;

    log_info(
        "Starting benchmark for %s.",
        drbg->name);

    status = benchmark_run(
        drbg,
        &config,
        &result);

    if (status != DRBG_STATUS_SUCCESS)
    {
        log_error(
            "Benchmark failed: %s (status %d).",
            status_to_string(status),
            (int)status);

        goto cleanup;
    }

    exit_code = EXIT_SUCCESS;

cleanup:

    if (entropy_initialized)
    {
        DRBGStatus shutdown_status =
            entropy_shutdown();

        if (shutdown_status != DRBG_STATUS_SUCCESS)
        {
            log_error(
                "Entropy shutdown failed: %s.",
                status_to_string(shutdown_status));

            exit_code = EXIT_FAILURE;
        }
    }

    return exit_code;
}