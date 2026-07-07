#ifndef CLI_H
#define CLI_H

#include "benchmark.h"
#include "drbg.h"

#include <stdbool.h>

bool cli_parse_arguments(
    int argc,
    char *argv[],
    BenchmarkConfig *config,
    const DRBG **drbg);

void cli_print_usage(const char *program_name);

#endif