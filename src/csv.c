#include "csv.h"
#include "utils.h"
#include <stdio.h>

bool csv_write_header(const char *filename)
{
    FILE *file = fopen(filename, "w");

    if (file == NULL)
        return false;

    fprintf(file,
        "Generator,"
        "Output_MB,"
        "Repetitions,"
        "Instantiate_ms,"
        "Generate_Avg_ms,"
        "Generate_Min_ms,"
        "Generate_Max_ms,"
        "Cleanup_ms,"
        "Throughput_MBps\n");

    fclose(file);

    return true;
}

bool csv_append_result(
    const char *filename,
    const char *generator_name,
    const BenchmarkConfig *config,
    const BenchmarkResult *result)
{
    FILE *file = fopen(filename, "a");

    if (file == NULL)
        return false;

    fprintf(file,
        "%s,"
        "%.2f,"
        "%zu,"
        "%.6f,"
        "%.6f,"
        "%.6f,"
        "%.6f,"
        "%.6f,"
        "%.2f\n",

        generator_name,

        bytes_to_megabytes(config->output_size),

        config->repetitions,

        result->instantiate_time_ms,

        result->average_generate_time_ms,

        result->min_generate_time_ms,

        result->max_generate_time_ms,

        result->cleanup_time_ms,

        result->throughput_MBps);

    fclose(file);

    return true;
}