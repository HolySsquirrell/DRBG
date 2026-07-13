#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stddef.h>
#include "drbg.h"
struct DRBG;

typedef struct BenchmarkConfig
{
    size_t output_size;

    size_t reseed_interval;

    int save_output;

    size_t repetitions;

    int verify_output;

} BenchmarkConfig;

typedef struct BenchmarkResult
{
    double instantiate_time_ms;
    double generate_time_ms;
    double reseed_time_ms;
    double cleanup_time_ms;
    double entropy_time_ms;
    double reseed_entropy_time_ms;
    double total_time_ms;

    double throughput_MBps;
    double effective_throughput_MBps;
    size_t reseed_count;
    size_t generate_request_count;
    double min_generate_time_ms;
    double max_generate_time_ms;
    double average_generate_time_ms;

} BenchmarkResult;

DRBGStatus benchmark_run(
    const DRBG *drbg,
    const BenchmarkConfig *config,
    BenchmarkResult *result);

#endif