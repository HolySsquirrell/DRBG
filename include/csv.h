#ifndef CSV_H
#define CSV_H

#include "benchmark.h"
#include <stdbool.h>

bool csv_write_header(const char *filename);

bool csv_append_result(
    const char *filename,
    const char *generator_name,
    const BenchmarkConfig *config,
    const BenchmarkResult *result);

#endif