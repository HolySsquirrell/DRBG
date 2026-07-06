#include "benchmark.h"
#include "dummy.h"

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
        &DummyDRBG,
        &config,
        &result);

    return 0;
}