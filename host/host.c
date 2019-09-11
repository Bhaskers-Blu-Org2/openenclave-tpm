// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "../tpm/tpm.h"
#include "tpm_u.h"

#define CONSOLE_ESCAPE "\033"
#define CONSOLE_RED CONSOLE_ESCAPE "[0;31m"
#define CONSOLE_GREEN CONSOLE_ESCAPE "[0;32m"
#define CONSOLE_RESET CONSOLE_ESCAPE "[0m"

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    int host_tests_result = 1;
    int enclave_tests_result = 1;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if ((argc != 1) && (argc != 2))
    {
        fprintf(
            stderr,
            "Usage: %s [ enclave_image_path ] [ --simulate  ]\n",
            argv[0]);
        goto exit;
    }

    printf("Running tests in host....\n");
    uint8_t insecure_seal_key[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    host_tests_result = run_tpm_tests(false, NULL, sizeof(insecure_seal_key));

    if (argc == 2)
    {
        printf("\nRunning tests in enclave....\n");

        printf("Starting enclave...\n");

        // Create the enclave
        result = oe_create_tpm_enclave(
            argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "oe_create_tpm_enclave(): result=%u (%s)\n",
                result,
                oe_result_str(result));
            goto exit;
        }

        printf("Calling into enclave...\n");

        // run the tpm tests in the enclave
        result = enclave_tpm_tests(enclave, &enclave_tests_result);
        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "calling into enclave_tpm_tests failed: result=%u (%s)\n",
                result,
                oe_result_str(result));
            goto exit;
        }
    }
    else
    {
        printf("\nSkipping enclave tests. Add enclave library path to command "
               "line to enable\n");
    }

exit:
    // Clean up the enclave if we created one
    if (enclave)
    {
        printf("\nTerminating enclave...\n");
        oe_terminate_enclave(enclave);
    }

    printf("\n\n************************\n");
    printf("************************\n");
    printf(
        "** host tests:    %s\n",
        host_tests_result == 1
            ? "skipped"
            : host_tests_result == 0 ? CONSOLE_GREEN "passed" CONSOLE_RESET
                                     : CONSOLE_RED "failed" CONSOLE_RESET);
    printf(
        "** enclave tests: %s\n",
        enclave_tests_result == 1
            ? "skipped"
            : enclave_tests_result == 0 ? CONSOLE_GREEN "passed" CONSOLE_RESET
                                        : CONSOLE_RED "failed" CONSOLE_RESET);
    printf("************************\n");
    printf("************************\n\n");

    if (host_tests_result == 0 && enclave_tests_result == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}
