#include "benchmark.h"

int main(void)
{
    BenchmarkConfig config =
    {
        .output_size = 1024 * 1024,
        .reseed_interval = 0,
        .save_output = 0,
        .repetitions = 1
    };

    BenchmarkResult result;

    benchmark_run(
        NULL,
        &config,
        &result);

    return 0;
}