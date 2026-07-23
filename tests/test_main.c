#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

bool test_hash_math(void);
bool test_hash_df(void);
bool test_hash_drbg_kat(void);
bool test_hash_drbg_nist_kat(void);
bool test_hash_drbg_nist_optional_inputs(void);
bool test_hash_drbg_nist_reseed(void);
bool test_hash_drbg_boundaries(void);

bool test_hmac_drbg_update(void);
bool test_hmac_drbg_nist_kat(void);
bool test_hmac_drbg_nist_optional_inputs(void);
bool test_hmac_drbg_nist_reseed(void);
bool test_hmac_drbg_nist_prediction_resistance(void);
bool test_hmac_drbg_boundaries(void);

typedef bool (*TestFunction)(void);

typedef struct
{
    const char *name;
    TestFunction function;
} TestCase;

int main(void)
{
    static const TestCase tests[] =
    {
        {"hash_math", test_hash_math},
        {"hash_df", test_hash_df},

        {"hash_drbg_regression", test_hash_drbg_kat},
        {"hash_drbg_nist_basic", test_hash_drbg_nist_kat},
        {
            "hash_drbg_nist_optional_inputs",
            test_hash_drbg_nist_optional_inputs
        },
        {
            "hash_drbg_nist_reseed",
            test_hash_drbg_nist_reseed
        },
        {
            "hash_drbg_boundaries",
            test_hash_drbg_boundaries
        },

        {"hmac_drbg_update", test_hmac_drbg_update},
        {"hmac_drbg_nist_basic", test_hmac_drbg_nist_kat},
        {
            "hmac_drbg_nist_optional_inputs",
            test_hmac_drbg_nist_optional_inputs
        },
        {
            "hmac_drbg_nist_reseed",
            test_hmac_drbg_nist_reseed
        },
        {
            "hmac_drbg_nist_prediction_resistance",
            test_hmac_drbg_nist_prediction_resistance
        },
        {
            "hmac_drbg_boundaries",
            test_hmac_drbg_boundaries
        }
    };

    const size_t test_count =
        sizeof(tests) / sizeof(tests[0]);

    size_t passed_count = 0;

    printf("DRBG test suite\n");
    printf("================\n");

    for (size_t i = 0; i < test_count; ++i)
    {
        printf("[TEST] %s\n", tests[i].name);

        if (tests[i].function())
        {
            printf("[PASS] %s\n", tests[i].name);
            ++passed_count;
        }
        else
        {
            printf("[FAIL] %s\n", tests[i].name);
        }
    }

    printf(
        "\n%zu/%zu tests passed\n",
        passed_count,
        test_count);

    return passed_count == test_count
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}