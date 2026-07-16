#include "drbg.h"
#include "hash_drbg.h"
#include "status.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_BUFFER_SIZE 16384U
#define VECTOR_OPERATIONS 2U

typedef struct
{
    uint8_t *data;
    size_t length;
    bool present;
} ByteBuffer;

typedef struct
{
    bool is_sha256;
    bool prediction_resistance;
    bool have_prediction_resistance;

    size_t entropy_input_bits;
    size_t nonce_bits;
    size_t personalization_bits;
    size_t additional_input_bits;
    size_t returned_bits;
} VectorConfig;

typedef struct
{
    bool active;
    bool have_count;
    unsigned long count;

    ByteBuffer entropy_input;
    ByteBuffer nonce;
    ByteBuffer personalization;

    ByteBuffer entropy_input_reseed;
    ByteBuffer additional_input_reseed;

    ByteBuffer additional_input[VECTOR_OPERATIONS];
    size_t additional_input_count;

    ByteBuffer entropy_input_pr[VECTOR_OPERATIONS];
    size_t entropy_input_pr_count;

    ByteBuffer returned_bits;
} VectorCase;

typedef struct
{
    size_t tested;
    size_t passed;
    size_t failed;
    size_t parse_errors;
} RunnerStats;

static void secure_clear(void *memory, size_t length)
{
    volatile uint8_t *bytes =
        (volatile uint8_t *)memory;

    while (memory != NULL && length > 0)
    {
        *bytes++ = 0;
        --length;
    }
}

static void buffer_clear(ByteBuffer *buffer)
{
    if (buffer == NULL)
    {
        return;
    }

    if (buffer->data != NULL)
    {
        secure_clear(buffer->data, buffer->length);
        free(buffer->data);
    }

    buffer->data = NULL;
    buffer->length = 0;
    buffer->present = false;
}

static void vector_case_clear(VectorCase *test_case)
{
    if (test_case == NULL)
    {
        return;
    }

    buffer_clear(&test_case->entropy_input);
    buffer_clear(&test_case->nonce);
    buffer_clear(&test_case->personalization);
    buffer_clear(&test_case->entropy_input_reseed);
    buffer_clear(&test_case->additional_input_reseed);
    buffer_clear(&test_case->returned_bits);

    for (size_t i = 0; i < VECTOR_OPERATIONS; ++i)
    {
        buffer_clear(&test_case->additional_input[i]);
        buffer_clear(&test_case->entropy_input_pr[i]);
    }

    memset(test_case, 0, sizeof(*test_case));
}

static char *trim(char *text)
{
    if (text == NULL)
    {
        return NULL;
    }

    while (isspace((unsigned char)*text))
    {
        ++text;
    }

    char *end = text + strlen(text);

    while (end > text && isspace((unsigned char)end[-1]))
    {
        --end;
    }

    *end = '\0';
    return text;
}

static bool text_equal_ignore_case(
    const char *left,
    const char *right)
{
    if (left == NULL || right == NULL)
    {
        return false;
    }

    while (*left != '\0' && *right != '\0')
    {
        if (tolower((unsigned char)*left) !=
            tolower((unsigned char)*right))
        {
            return false;
        }

        ++left;
        ++right;
    }

    return *left == '\0' && *right == '\0';
}

static bool parse_size_value(
    const char *text,
    size_t *value)
{
    if (text == NULL || value == NULL)
    {
        return false;
    }

    errno = 0;
    char *end = NULL;

    unsigned long long parsed =
        strtoull(text, &end, 10);

    if (errno == ERANGE ||
        end == text ||
        *trim(end) != '\0' ||
        parsed > SIZE_MAX)
    {
        return false;
    }

    *value = (size_t)parsed;
    return true;
}

static int hex_nibble(char character)
{
    if (character >= '0' && character <= '9')
    {
        return character - '0';
    }

    character =
        (char)tolower((unsigned char)character);

    if (character >= 'a' && character <= 'f')
    {
        return character - 'a' + 10;
    }

    return -1;
}

static bool buffer_set_hex(
    ByteBuffer *buffer,
    const char *hex_text)
{
    if (buffer == NULL || hex_text == NULL)
    {
        return false;
    }

    buffer_clear(buffer);

    size_t hex_length = strlen(hex_text);

    if ((hex_length % 2U) != 0U)
    {
        return false;
    }

    buffer->present = true;
    buffer->length = hex_length / 2U;

    if (buffer->length == 0)
    {
        return true;
    }

    buffer->data = malloc(buffer->length);

    if (buffer->data == NULL)
    {
        buffer->length = 0;
        buffer->present = false;
        return false;
    }

    for (size_t i = 0; i < buffer->length; ++i)
    {
        int high = hex_nibble(hex_text[i * 2U]);
        int low = hex_nibble(hex_text[i * 2U + 1U]);

        if (high < 0 || low < 0)
        {
            buffer_clear(buffer);
            return false;
        }

        buffer->data[i] =
            (uint8_t)((high << 4) | low);
    }

    return true;
}

static const ByteBuffer *optional_operation_input(
    const ByteBuffer inputs[VECTOR_OPERATIONS],
    size_t count,
    size_t index)
{
    static const ByteBuffer empty =
    {
        .data = NULL,
        .length = 0,
        .present = true
    };

    if (index < count)
    {
        return &inputs[index];
    }

    return &empty;
}

static bool bits_to_bytes(
    size_t bits,
    size_t *bytes)
{
    if (bytes == NULL || (bits % 8U) != 0U)
    {
        return false;
    }

    *bytes = bits / 8U;
    return true;
}

static bool require_buffer_length(
    const char *file_name,
    unsigned long count,
    const char *field_name,
    const ByteBuffer *buffer,
    size_t expected_length,
    bool allow_missing_when_empty)
{
    if (buffer == NULL)
    {
        return false;
    }

    if (!buffer->present)
    {
        if (allow_missing_when_empty && expected_length == 0)
        {
            return true;
        }

        fprintf(
            stderr,
            "%s: COUNT %lu: missing %s\n",
            file_name,
            count,
            field_name);

        return false;
    }

    if (buffer->length != expected_length)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: %s has %zu bytes, expected %zu\n",
            file_name,
            count,
            field_name,
            buffer->length,
            expected_length);

        return false;
    }

    return true;
}

static bool validate_case(
    const char *file_name,
    const VectorConfig *config,
    const VectorCase *test_case)
{
    size_t entropy_bytes = 0;
    size_t nonce_bytes = 0;
    size_t personalization_bytes = 0;
    size_t additional_bytes = 0;
    size_t returned_bytes = 0;

    if (config == NULL || test_case == NULL)
    {
        return false;
    }

    if (!config->have_prediction_resistance ||
        !bits_to_bytes(config->entropy_input_bits, &entropy_bytes) ||
        !bits_to_bytes(config->nonce_bits, &nonce_bytes) ||
        !bits_to_bytes(config->personalization_bits, &personalization_bytes) ||
        !bits_to_bytes(config->additional_input_bits, &additional_bytes) ||
        !bits_to_bytes(config->returned_bits, &returned_bytes))
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: invalid or non-byte-aligned configuration\n",
            file_name,
            test_case->count);

        return false;
    }

    if (returned_bytes == 0 ||
        returned_bytes > HASH_DRBG_MAX_BYTES_PER_REQUEST)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: unsupported ReturnedBitsLen (%zu bits)\n",
            file_name,
            test_case->count,
            config->returned_bits);

        return false;
    }

    if (!require_buffer_length(
            file_name,
            test_case->count,
            "EntropyInput",
            &test_case->entropy_input,
            entropy_bytes,
            false) ||
        !require_buffer_length(
            file_name,
            test_case->count,
            "Nonce",
            &test_case->nonce,
            nonce_bytes,
            false) ||
        !require_buffer_length(
            file_name,
            test_case->count,
            "PersonalizationString",
            &test_case->personalization,
            personalization_bytes,
            true) ||
        !require_buffer_length(
            file_name,
            test_case->count,
            "ReturnedBits",
            &test_case->returned_bits,
            returned_bytes,
            false))
    {
        return false;
    }

    if (additional_bytes > 0 &&
        test_case->additional_input_count != VECTOR_OPERATIONS)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: expected two AdditionalInput values\n",
            file_name,
            test_case->count);

        return false;
    }

    if (test_case->additional_input_count != 0 &&
        test_case->additional_input_count != VECTOR_OPERATIONS)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: found %zu AdditionalInput values\n",
            file_name,
            test_case->count,
            test_case->additional_input_count);

        return false;
    }

    for (size_t i = 0;
         i < test_case->additional_input_count;
         ++i)
    {
        if (!require_buffer_length(
                file_name,
                test_case->count,
                "AdditionalInput",
                &test_case->additional_input[i],
                additional_bytes,
                additional_bytes == 0))
        {
            return false;
        }
    }

    if (config->prediction_resistance)
    {
        if (test_case->entropy_input_pr_count != VECTOR_OPERATIONS)
        {
            fprintf(
                stderr,
                "%s: COUNT %lu: expected two EntropyInputPR values\n",
                file_name,
                test_case->count);

            return false;
        }

        for (size_t i = 0; i < VECTOR_OPERATIONS; ++i)
        {
            if (!require_buffer_length(
                    file_name,
                    test_case->count,
                    "EntropyInputPR",
                    &test_case->entropy_input_pr[i],
                    entropy_bytes,
                    false))
            {
                return false;
            }
        }
    }
    else if (test_case->entropy_input_reseed.present)
    {
        if (!require_buffer_length(
                file_name,
                test_case->count,
                "EntropyInputReseed",
                &test_case->entropy_input_reseed,
                entropy_bytes,
                false) ||
            !require_buffer_length(
                file_name,
                test_case->count,
                "AdditionalInputReseed",
                &test_case->additional_input_reseed,
                additional_bytes,
                true))
        {
            return false;
        }
    }

    return true;
}

static bool execute_case(
    const char *file_name,
    const VectorConfig *config,
    const VectorCase *test_case,
    bool verbose)
{
    if (!validate_case(file_name, config, test_case))
    {
        return false;
    }

    bool passed = false;
    void *ctx = NULL;
    uint8_t *output = NULL;

    ctx = calloc(1, HashDRBG.context_size);
    output = malloc(test_case->returned_bits.length);

    if (ctx == NULL || output == NULL)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: allocation failure\n",
            file_name,
            test_case->count);

        goto cleanup;
    }

    const uint8_t *personalization =
        test_case->personalization.present
            ? test_case->personalization.data
            : NULL;

    size_t personalization_length =
        test_case->personalization.present
            ? test_case->personalization.length
            : 0;

    DRBGStatus status =
        HashDRBG.instantiate(
            ctx,
            test_case->entropy_input.data,
            test_case->entropy_input.length,
            test_case->nonce.data,
            test_case->nonce.length,
            personalization,
            personalization_length);

    if (status != DRBG_STATUS_SUCCESS)
    {
        fprintf(
            stderr,
            "%s: COUNT %lu: instantiate returned status %d\n",
            file_name,
            test_case->count,
            (int)status);

        goto cleanup;
    }

    if (config->prediction_resistance)
    {
        for (size_t operation = 0;
             operation < VECTOR_OPERATIONS;
             ++operation)
        {
            const ByteBuffer *additional =
                optional_operation_input(
                    test_case->additional_input,
                    test_case->additional_input_count,
                    operation);

            status =
                HashDRBG.reseed(
                    ctx,
                    test_case->entropy_input_pr[operation].data,
                    test_case->entropy_input_pr[operation].length,
                    additional->data,
                    additional->length);

            if (status != DRBG_STATUS_SUCCESS)
            {
                fprintf(
                    stderr,
                    "%s: COUNT %lu: PR reseed %zu returned status %d\n",
                    file_name,
                    test_case->count,
                    operation + 1U,
                    (int)status);

                goto cleanup;
            }

            status =
                HashDRBG.generate(
                    ctx,
                    output,
                    test_case->returned_bits.length,
                    NULL,
                    0);

            if (status != DRBG_STATUS_SUCCESS)
            {
                fprintf(
                    stderr,
                    "%s: COUNT %lu: PR generate %zu returned status %d\n",
                    file_name,
                    test_case->count,
                    operation + 1U,
                    (int)status);

                goto cleanup;
            }
        }
    }
    else
    {
        if (test_case->entropy_input_reseed.present)
        {
            const uint8_t *additional_reseed =
                test_case->additional_input_reseed.present
                    ? test_case->additional_input_reseed.data
                    : NULL;

            size_t additional_reseed_length =
                test_case->additional_input_reseed.present
                    ? test_case->additional_input_reseed.length
                    : 0;

            status =
                HashDRBG.reseed(
                    ctx,
                    test_case->entropy_input_reseed.data,
                    test_case->entropy_input_reseed.length,
                    additional_reseed,
                    additional_reseed_length);

            if (status != DRBG_STATUS_SUCCESS)
            {
                fprintf(
                    stderr,
                    "%s: COUNT %lu: reseed returned status %d\n",
                    file_name,
                    test_case->count,
                    (int)status);

                goto cleanup;
            }
        }

        for (size_t operation = 0;
             operation < VECTOR_OPERATIONS;
             ++operation)
        {
            const ByteBuffer *additional =
                optional_operation_input(
                    test_case->additional_input,
                    test_case->additional_input_count,
                    operation);

            status =
                HashDRBG.generate(
                    ctx,
                    output,
                    test_case->returned_bits.length,
                    additional->data,
                    additional->length);

            if (status != DRBG_STATUS_SUCCESS)
            {
                fprintf(
                    stderr,
                    "%s: COUNT %lu: generate %zu returned status %d\n",
                    file_name,
                    test_case->count,
                    operation + 1U,
                    (int)status);

                goto cleanup;
            }
        }
    }

    if (memcmp(
            output,
            test_case->returned_bits.data,
            test_case->returned_bits.length) != 0)
    {
        size_t difference = 0;

        while (difference < test_case->returned_bits.length &&
               output[difference] ==
                   test_case->returned_bits.data[difference])
        {
            ++difference;
        }

        fprintf(
            stderr,
            "%s: COUNT %lu: output mismatch at byte %zu: "
            "got %02X, expected %02X\n",
            file_name,
            test_case->count,
            difference,
            output[difference],
            test_case->returned_bits.data[difference]);

        goto cleanup;
    }

    if (verbose)
    {
        printf(
            "[PASS] %s: SHA-256 COUNT = %lu\n",
            file_name,
            test_case->count);
    }

    passed = true;

cleanup:

    if (ctx != NULL && HashDRBG.uninstantiate != NULL)
    {
        HashDRBG.uninstantiate(ctx);
    }

    if (output != NULL)
    {
        secure_clear(
            output,
            test_case->returned_bits.length);
    }

    free(output);
    free(ctx);

    return passed;
}

static bool parse_config_line(
    VectorConfig *config,
    char *content)
{
    char *equals = strchr(content, '=');

    if (equals == NULL)
    {
        memset(config, 0, sizeof(*config));
        config->is_sha256 =
            text_equal_ignore_case(trim(content), "SHA-256");

        return true;
    }

    *equals = '\0';

    char *key = trim(content);
    char *value = trim(equals + 1);

    if (strcmp(key, "PredictionResistance") == 0)
    {
        if (text_equal_ignore_case(value, "True"))
        {
            config->prediction_resistance = true;
        }
        else if (text_equal_ignore_case(value, "False"))
        {
            config->prediction_resistance = false;
        }
        else
        {
            return false;
        }

        config->have_prediction_resistance = true;
        return true;
    }

    if (strcmp(key, "EntropyInputLen") == 0)
    {
        return parse_size_value(
            value,
            &config->entropy_input_bits);
    }

    if (strcmp(key, "NonceLen") == 0)
    {
        return parse_size_value(
            value,
            &config->nonce_bits);
    }

    if (strcmp(key, "PersonalizationStringLen") == 0)
    {
        return parse_size_value(
            value,
            &config->personalization_bits);
    }

    if (strcmp(key, "AdditionalInputLen") == 0)
    {
        return parse_size_value(
            value,
            &config->additional_input_bits);
    }

    if (strcmp(key, "ReturnedBitsLen") == 0)
    {
        return parse_size_value(
            value,
            &config->returned_bits);
    }

    return true;
}

static bool parse_case_field(
    const char *file_name,
    size_t line_number,
    VectorCase *test_case,
    char *key,
    char *value)
{
    ByteBuffer *destination = NULL;

    if (strcmp(key, "EntropyInput") == 0)
    {
        destination = &test_case->entropy_input;
    }
    else if (strcmp(key, "Nonce") == 0)
    {
        destination = &test_case->nonce;
    }
    else if (strcmp(key, "PersonalizationString") == 0)
    {
        destination = &test_case->personalization;
    }
    else if (strcmp(key, "EntropyInputReseed") == 0)
    {
        destination = &test_case->entropy_input_reseed;
    }
    else if (strcmp(key, "AdditionalInputReseed") == 0)
    {
        destination = &test_case->additional_input_reseed;
    }
    else if (strcmp(key, "AdditionalInput") == 0)
    {
        if (test_case->additional_input_count >= VECTOR_OPERATIONS)
        {
            fprintf(
                stderr,
                "%s:%zu: too many AdditionalInput fields\n",
                file_name,
                line_number);

            return false;
        }

        destination =
            &test_case->additional_input[
                test_case->additional_input_count++];
    }
    else if (strcmp(key, "EntropyInputPR") == 0)
    {
        if (test_case->entropy_input_pr_count >= VECTOR_OPERATIONS)
        {
            fprintf(
                stderr,
                "%s:%zu: too many EntropyInputPR fields\n",
                file_name,
                line_number);

            return false;
        }

        destination =
            &test_case->entropy_input_pr[
                test_case->entropy_input_pr_count++];
    }
    else if (strcmp(key, "ReturnedBits") == 0)
    {
        destination = &test_case->returned_bits;
    }
    else
    {
        return true;
    }

    if (!buffer_set_hex(destination, value))
    {
        fprintf(
            stderr,
            "%s:%zu: invalid hexadecimal data for %s\n",
            file_name,
            line_number,
            key);

        return false;
    }

    return true;
}

static bool parse_count(
    const char *text,
    unsigned long *count)
{
    if (text == NULL || count == NULL)
    {
        return false;
    }

    errno = 0;
    char *end = NULL;

    unsigned long parsed =
        strtoul(text, &end, 10);

    if (errno == ERANGE ||
        end == text ||
        *trim(end) != '\0')
    {
        return false;
    }

    *count = parsed;
    return true;
}

static bool process_file(
    const char *file_name,
    bool verbose,
    RunnerStats *total_stats)
{
    FILE *file = fopen(file_name, "rb");

    if (file == NULL)
    {
        fprintf(
            stderr,
            "Could not open vector file: %s\n",
            file_name);

        total_stats->parse_errors++;
        return false;
    }

    VectorConfig config = {0};
    VectorCase test_case = {0};
    RunnerStats file_stats = {0};

    char line_buffer[LINE_BUFFER_SIZE];
    size_t line_number = 0;
    bool file_ok = true;

    while (fgets(
               line_buffer,
               (int)sizeof(line_buffer),
               file) != NULL)
    {
        ++line_number;

        if (line_number == 1 &&
            (unsigned char)line_buffer[0] == 0xEF &&
            (unsigned char)line_buffer[1] == 0xBB &&
            (unsigned char)line_buffer[2] == 0xBF)
        {
            memmove(
                line_buffer,
                line_buffer + 3,
                strlen(line_buffer + 3) + 1U);
        }

        if (strchr(line_buffer, '\n') == NULL &&
            !feof(file))
        {
            fprintf(
                stderr,
                "%s:%zu: input line exceeds %u bytes\n",
                file_name,
                line_number,
                LINE_BUFFER_SIZE - 1U);

            file_stats.parse_errors++;
            file_ok = false;
            break;
        }

        char *line = trim(line_buffer);

        if (*line == '\0' || *line == '#')
        {
            continue;
        }

        if (*line == '[')
        {
            size_t length = strlen(line);

            if (length < 2U || line[length - 1U] != ']')
            {
                fprintf(
                    stderr,
                    "%s:%zu: malformed configuration line\n",
                    file_name,
                    line_number);

                file_stats.parse_errors++;
                file_ok = false;
                continue;
            }

            line[length - 1U] = '\0';

            if (!parse_config_line(
                    &config,
                    trim(line + 1)))
            {
                fprintf(
                    stderr,
                    "%s:%zu: invalid configuration value\n",
                    file_name,
                    line_number);

                file_stats.parse_errors++;
                file_ok = false;
            }

            continue;
        }

        char *equals = strchr(line, '=');

        if (equals == NULL)
        {
            continue;
        }

        *equals = '\0';

        char *key = trim(line);
        char *value = trim(equals + 1);

        if (strcmp(key, "COUNT") == 0)
        {
            if (test_case.active &&
                !test_case.returned_bits.present)
            {
                fprintf(
                    stderr,
                    "%s:%zu: previous SHA-256 case has no ReturnedBits\n",
                    file_name,
                    line_number);

                file_stats.parse_errors++;
                file_ok = false;
            }

            vector_case_clear(&test_case);

            if (!parse_count(value, &test_case.count))
            {
                fprintf(
                    stderr,
                    "%s:%zu: invalid COUNT value\n",
                    file_name,
                    line_number);

                file_stats.parse_errors++;
                file_ok = false;
                continue;
            }

            test_case.have_count = true;
            test_case.active = config.is_sha256;
            continue;
        }

        if (!test_case.active)
        {
            continue;
        }

        if (!parse_case_field(
                file_name,
                line_number,
                &test_case,
                key,
                value))
        {
            file_stats.parse_errors++;
            file_ok = false;
            continue;
        }

        if (strcmp(key, "ReturnedBits") == 0)
        {
            file_stats.tested++;

            if (execute_case(
                    file_name,
                    &config,
                    &test_case,
                    verbose))
            {
                file_stats.passed++;
            }
            else
            {
                file_stats.failed++;
                file_ok = false;
            }

            vector_case_clear(&test_case);
        }
    }

    if (ferror(file))
    {
        fprintf(
            stderr,
            "Read error while processing %s\n",
            file_name);

        file_stats.parse_errors++;
        file_ok = false;
    }

    if (test_case.active && test_case.have_count)
    {
        fprintf(
            stderr,
            "%s: incomplete SHA-256 case at end of file\n",
            file_name);

        file_stats.parse_errors++;
        file_ok = false;
    }

    vector_case_clear(&test_case);
    fclose(file);

    total_stats->tested += file_stats.tested;
    total_stats->passed += file_stats.passed;
    total_stats->failed += file_stats.failed;
    total_stats->parse_errors += file_stats.parse_errors;

    printf(
        "[FILE] %s: %zu/%zu passed, %zu parse errors\n",
        file_name,
        file_stats.passed,
        file_stats.tested,
        file_stats.parse_errors);

    return file_ok;
}

static void print_usage(const char *program_name)
{
    fprintf(
        stderr,
        "Usage: %s [--verbose] <Hash_DRBG.rsp> "
        "[more .rsp files ...]\n",
        program_name);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (HashDRBG.context_size == 0 ||
        HashDRBG.instantiate == NULL ||
        HashDRBG.generate == NULL ||
        HashDRBG.reseed == NULL ||
        HashDRBG.uninstantiate == NULL)
    {
        fprintf(stderr, "HashDRBG descriptor is incomplete.\n");
        return EXIT_FAILURE;
    }

    bool verbose = false;
    int first_file = 1;

    if (strcmp(argv[1], "--verbose") == 0)
    {
        verbose = true;
        first_file = 2;
    }

    if (first_file >= argc)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    RunnerStats stats = {0};
    bool all_files_ok = true;

    for (int argument = first_file;
         argument < argc;
         ++argument)
    {
        if (!process_file(
                argv[argument],
                verbose,
                &stats))
        {
            all_files_ok = false;
        }
    }

    printf("\nNIST Hash_DRBG SHA-256 summary\n");
    printf("===============================\n");
    printf("Tested       : %zu\n", stats.tested);
    printf("Passed       : %zu\n", stats.passed);
    printf("Failed       : %zu\n", stats.failed);
    printf("Parse errors : %zu\n", stats.parse_errors);

    if (stats.tested == 0)
    {
        fprintf(
            stderr,
            "No SHA-256 Hash_DRBG test cases were found.\n");

        return EXIT_FAILURE;
    }

    return all_files_ok &&
           stats.failed == 0 &&
           stats.parse_errors == 0
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
