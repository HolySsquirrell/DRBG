#include "benchmark.h"

#include "logger.h"

int benchmark_run(
    const struct DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result)
{
    (void)drbg;
    (void)config;
    (void)result;

    log_info("Benchmark framework initialized.");

    return 0;
}