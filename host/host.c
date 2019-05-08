// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "../tpm/tpm.h"
#include "tpm_u.h"

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

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if ((argc != 1 )&& (argc != 2))
    {
        fprintf(
            stderr, "Usage: %s [ enclave_image_path ] [ --simulate  ]\n", argv[0]);
        goto exit;
    }

    printf("Running tests in host....\n");
    int ret = run_tpm_tests();
    if (ret != 0)
    {
        fprintf(stderr, "Tests failed to run in host %d\n", ret);
    }

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
        result = enclave_tpm_tests(enclave, &ret);
        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "calling into enclave_tpm_tests failed: result=%u (%s)\n",
                result,
                oe_result_str(result));
            goto exit;
        }
        else if (ret != 0)
        {
            fprintf(stderr, "enclave_tpm_tests returned error, %i", ret);
        }
    }
    else
    {
        printf("\nSkipping enclave tests. Add enclave library path to command line to enable\n");
    }
    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
    {
        printf("\nTerminating enclave...\n");
        oe_terminate_enclave(enclave);
    }

    printf("\nDone!\n");

    return ret;
}
