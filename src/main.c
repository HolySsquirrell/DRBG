#include "benchmark.h"
#include "dummy.h"
#include "utils.h"
#include "config.h"
#include "csv.h"
#include "cli.h"
#include "entropy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    BenchmarkConfig config;
    BenchmarkResult result;
    const DRBG *drbg;

    if (!cli_parse_arguments(
            argc,
            argv,
            &config,
            &drbg))
    {
        return DRBG_EXIT_FAILURE;
    }
    if (entropy_initialize() != DRBG_STATUS_SUCCESS)
    {
        return DRBG_EXIT_FAILURE;
    }
    csv_write_header(RESULTS_CSV_FILE);
    benchmark_run(
        drbg,
        &config,
        &result);

    return 0;
    entropy_shutdown();
}