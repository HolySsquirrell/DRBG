#include "cli.h"

#include "logger.h"
#include "registry.h"
#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REPETITIONS 100

static bool parse_size(
    const char *text,
    size_t *bytes)
{
    char *end;

    unsigned long long value = strtoull(text, &end, 10);

    if (end == text || value == 0)
        return false;

    char suffix[3];

    suffix[0] = (char)toupper((unsigned char)end[0]);
    suffix[1] = (char)toupper((unsigned char)end[1]);
    suffix[2] = '\0';

    if (strcmp(suffix, "KB") == 0)
    {
        *bytes = KB(value);
        return true;
    }

    if (strcmp(suffix, "MB") == 0)
    {
        *bytes = MB(value);
        return true;
    }

    if (strcmp(suffix, "GB") == 0)
    {
        *bytes = GB(value);
        return true;
    }

    return false;
}

void cli_print_usage(const char *program_name)
{
    printf("\n");
    printf("DRBG Benchmark Framework\n");
    printf("------------------------\n\n");

    printf("Usage:\n");
    printf("  %s <generator> <size> [repetitions] [options]\n\n",
           program_name);

    printf("Generators:\n");

    const DRBGEntry *entries = registry_entries();

    for (size_t i = 0; i < registry_count(); ++i)
    {
        printf("  %s\n", entries[i].name);
    }

    printf("\n");

    printf("Examples:\n");
    printf("  %s dummy 10MB\n", program_name);
    printf("  %s dummy 1GB 100\n", program_name);
    printf("  %s dummy 500MB --save\n", program_name);
    printf("  %s dummy 1GB 500 --verify\n\n", program_name);

    printf("Options:\n");
    printf("  --save          Save generated output\n");
    printf("  --verify        Enable verification\n");
    printf("  --no-verify     Disable verification\n");
    printf("  --help          Display this help\n\n");
}

bool cli_parse_arguments(
    int argc,
    char *argv[],
    BenchmarkConfig *config,
    const DRBG **drbg)
{
    if (argc < 2)
    {
        cli_print_usage(argv[0]);
        return false;
    }

    if (strcmp(argv[1], "--help") == 0)
    {
        cli_print_usage(argv[0]);
        return false;
    }

    memset(config, 0, sizeof(*config));

    config->repetitions = DEFAULT_REPETITIONS;
    config->save_output = false;
    config->verify_output = false;
    config->reseed_interval = 0;

    *drbg = drbg_find(argv[1]);

    if (*drbg == NULL)
    {
        log_error("Unknown DRBG: %s", argv[1]);
        return false;
    }

    if (argc < 3)
    {
        log_error("Missing output size.");
        cli_print_usage(argv[0]);
        return false;
    }

    if (!parse_size(argv[2], &config->output_size))
    {
        log_error("Invalid output size: %s", argv[2]);
        return false;
    }

    int arg = 3;

    if (arg < argc && strncmp(argv[arg], "--", 2) != 0)
    {
        config->repetitions = strtoull(argv[arg], NULL, 10);

        if (config->repetitions == 0)
        {
            log_error("Repetitions must be greater than zero.");
            return false;
        }

        arg++;
    }


    while (arg < argc)
    {
        if (strcmp(argv[arg], "--save") == 0)
        {
            config->save_output = true;
        }
        else if (strcmp(argv[arg], "--verify") == 0)
        {
            config->verify_output = true;
        }
        else if (strcmp(argv[arg], "--no-verify") == 0)
        {
            config->verify_output = false;
        }
        else if (strcmp(argv[arg], "--help") == 0)
        {
            cli_print_usage(argv[0]);
            return false;
        }
        else
        {
            log_error("Unknown option: %s", argv[arg]);
            return false;
        }

        arg++;
    }

    return true;
}