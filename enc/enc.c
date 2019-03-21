// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>

#include "tpm_t.h"

#include <tss2_esys.h>


void enclave_tpm_list_nv_indexes()
{
    ESYS_CONTEXT *ectx = NULL;
    TSS2_RC rval;
    
    rval = Esys_Initialize(&ectx, NULL, NULL);
    if (rval == TSS2_RC_SUCCESS)
    {
        printf("Succeeded: Esys_Initialize\n");

        TPMS_CAPABILITY_DATA *capabilityData;
        rval = Esys_GetCapability(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES, TPM2_HT_NV_INDEX, TPM2_PT_NV_INDEX_MAX, NULL, &capabilityData);
        if (rval == TSS2_RC_SUCCESS)
        {
            printf("Succeeded: Esys_GetCapability\n");

            UINT32 i;
            for (i = 0; i < capabilityData->data.handles.count; i++)
            {
                TPMI_RH_NV_INDEX index = capabilityData->data.handles.handle[i];
                ESYS_TR tr_object;
                rval = Esys_TR_FromTPMPublic(ectx, index, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tr_object);
                if (rval == TSS2_RC_SUCCESS)
                {
                    printf("Succeeded: Esys_TR_FromTPMPublic\n");

                    TPM2B_NV_PUBLIC *nv_public;
                    rval = Esys_NV_ReadPublic(ectx, tr_object, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_public, NULL);
                    if (rval == TSS2_RC_SUCCESS)
                    {
                        printf("Succeeded: Esys_NV_ReadPublic\n");

                        free(nv_public);
                    }
                    else
                    {
                        printf("Failed(%u): Esys_NV_ReadPublic\n", rval);
                    }

                    rval = Esys_TR_Close(ectx, &tr_object);
                    if (rval == TSS2_RC_SUCCESS)
                    {
                        printf("Succeeded: Esys_TR_Close\n");
                    }
                    else
                    {
                        printf("Failed(%u): Esys_TR_Close\n", rval);
                    }
                }
                else
                {
                    printf("Failed(%u): Esys_TR_FromTPMPublic\n", rval);
                }

            }
        }
        else
        {
            printf("Failed(%u): Esys_GetCapability, failed to get max number of NV indexes\n", rval);
        }

        Esys_Finalize(&ectx);
    }
    else
    {
        printf("Failed(%u): Esys_Initialize\n", rval);
    }
}
