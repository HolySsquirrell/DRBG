#include "benchmark.h"
#include "dummy.h"
#include "utils.h"
int main(void)
{
    BenchmarkConfig config =
    {
        .output_size = MB(10),
        .reseed_interval = 0,
        .save_output = 0,
        .repetitions = 100
    };

    BenchmarkResult result;

    benchmark_run(
        &DummyDRBG,
        &config,
        &result);

    return 0;
}