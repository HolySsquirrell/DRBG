#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stddef.h>

struct DRBG;

typedef struct
{
    size_t output_size;
    size_t reseed_interval;
    int save_output;
    unsigned int repetitions;
} BenchmarkConfig;

typedef struct
{
    double instantiate_time_ms;
    double generate_time_ms;
    double reseed_time_ms;
    double cleanup_time_ms;

    double total_time_ms;

    double throughput_MBps;
} BenchmarkResult;

int benchmark_run(
    const struct DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result);

#endif