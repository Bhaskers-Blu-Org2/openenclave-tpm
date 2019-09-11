// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <sys/mount.h>

#include "../tpm/tpm.h"

int enclave_tpm_tests()
{
    int return_value = 0;
    int int_return;
    oe_result_t oe_result;

    // Enable host filesystem access from enclave.
    // This calls into the host.
    // Make sure any file access is secure!
    oe_result = oe_load_module_host_file_system();
    if (oe_result != OE_OK)
    {
        printf("Failed to load host filesystem in enclave, 0x%X\n", oe_result);
        return_value = -1;
    }
    else
    {
        // Mount the host filesystem to root. This is needed
        // for the TPM library that accesses /dev/tpm*
        int_return = mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL);
        if (int_return != 0)
        {
            printf("Failed to mount hostfs from '/'\n");
            return_value = -1;
        }
        else
        {
            uint8_t* seal_key = NULL;
            size_t seal_key_size = 0;
            uint8_t* info = NULL;
            size_t info_size = 0;

            // Get a seal key from the enclave itself to secure communication to
            // the session with the TPM itself. This makes sure the unsecure
            // host, that performs the actual IO on our behalf, cannot see the
            // data.
            oe_result = oe_get_seal_key_by_policy(
                OE_SEAL_POLICY_UNIQUE,
                &seal_key,
                &seal_key_size,
                &info,
                &info_size);
            if (oe_result == OE_OK)
            {
                int_return = run_tpm_tests(true, seal_key, seal_key_size);
                if (int_return != 0)
                {
                    printf("run_tpm_tests failed\n");
                    return_value = -1;
                }
                oe_free_key(seal_key, seal_key_size, info, info_size);
            }
            else
            {
                printf(
                    "Failed: oe_get_seal_key_by_policy returned %u\n",
                    oe_result);
                return_value = -1;
            }

            int_return = umount("/");
            if (int_return != 0)
            {
                printf("Failed to unmount hostfs from '/'\n");
                return_value = -1;
            }
        }
    }

    return return_value;
}
