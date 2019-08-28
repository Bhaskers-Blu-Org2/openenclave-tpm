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

    oe_load_module_host_file_system();
    oe_load_module_host_epoll();

    int_return = mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL);
    if (int_return != 0)
    {
        printf("Failed to mount hostfs from '/'\n");
        return_value = -1;
    }
    else
    {
        int_return = run_tpm_tests();
        if (int_return != 0)
        {
            printf("run_tpm_tests failed\n");
            return_value = -1;
        }

        int_return = umount("/");
        if (int_return != 0)
        {
            printf("Failed to unmount hostfs from '/'\n");
            return_value = -1;
        }
    }

    return return_value;
}
