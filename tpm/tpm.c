// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
// openenclave mount function
#include <sys/mount.h>

//#include "tpm_t.h"

#include <tss2_esys.h>

// Global TPM context handle used for most top-level TPM APIs
static ESYS_CONTEXT* g_esys_context = NULL;
#define bool _Bool
#define TPM_COUNTER_ID 0x1500018

// conversion taken from tpm2-tools for now
// Needed to convert endianness of certain parameters passed to the TPM
bool tpm2_util_is_big_endian(void)
{
    uint32_t test_word;
    uint8_t* test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t*)(&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size)                    \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) \
    {                                                        \
        UINT##size converted;                                \
        UINT8* bytes = (UINT8*)&data;                        \
        UINT8* tmp = (UINT8*)&converted;                     \
                                                             \
        size_t i;                                            \
        for (i = 0; i < sizeof(UINT##size); i++)             \
        {                                                    \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1];      \
        }                                                    \
                                                             \
        return converted;                                    \
    }

STRING_BYTES_ENDIAN_CONVERT(32)

#define STRING_BYTES_ENDIAN_HTON(size)                  \
    UINT##size tpm2_util_hton_##size(UINT##size data)   \
    {                                                   \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        if (is_big_endian)                              \
        {                                               \
            return data;                                \
        }                                               \
                                                        \
        return tpm2_util_endian_swap_##size(data);      \
    }

STRING_BYTES_ENDIAN_HTON(32)

UINT32 tpm2_util_ntoh_32(UINT32 data)
{
    return tpm2_util_hton_32(data);
}

// Initialize anything that is globally used within this enclave.
// Need to call the deinitialize() function to clean anything up.
int tpm_initialize()
{
    int return_value = 0;

    // Mount the file system to the hostfs driver. This is mapping the root
    // so all filesystem calls will be routed to the insecure host.
    // The TPM code opens /dev/tpm0 or /dev/tpmrm0. We could map both these
    // to the host so no other files accidentally get written.
    //    int int_return = mount("/", "/", "hostfs", 0, NULL);
    //    if (int_return != 0)
    //    {
    //        printf("Failed to mount hostfs to '/'");
    //        return_value = -1;
    //    }

    // Initialize TPM ESYS
    TSS2_RC rc_return = Esys_Initialize(&g_esys_context, NULL, NULL);
    if (rc_return != TSS2_RC_SUCCESS)
    {
        printf("Failed(%u): Esys_Initialize\n", rc_return);
        return_value = -1;
    }

    return return_value;
}

// Clean up anything that was initialized in the initialize() function.
int tpm_deinitialize()
{
    //    int int_return = umount("/");
    //    if (int_return != 0)
    //    {
    //        printf("Failed to unmount hostfs from '/'");
    //    }

    if (g_esys_context)
    {
        Esys_Finalize(&g_esys_context);
    }
}

// get_capabilities is more just a validation that we can actually talk
// to the TPM. In this case it is associated with number of NV Indexes,
// but could have been anything.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_get_capabilities()
{
    int return_value = 0;
    TSS2_RC rc_return;
    TPMS_CAPABILITY_DATA* capabilityData;

    rc_return = Esys_GetCapability(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_HANDLES,
        tpm2_util_hton_32(TPM2_HT_NV_INDEX),
        TPM2_PT_NV_INDEX_MAX,
        NULL,
        &capabilityData);
    if (rc_return == TSS2_RC_SUCCESS)
    {
        printf(
            "Succeeded: Esys_GetCapability, Number of used NV Indexes = %u\n",
            capabilityData->data.handles.count);
    }
    else
    {
        printf(
            "Failed(%u): Esys_GetCapability, failed to get max number of NV "
            "indexes\n",
            rc_return);
        return_value = -1;
    }

    return return_value;
}

// allocate_nv_counter calls into the TPM to allocate a 8-byte counter
// giving it the index passed in.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_allocate_nv_counter()
{
    int return_value = 0;
    uint32_t index_handle = TPM_COUNTER_ID;
    TSS2_RC rc_return;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    ESYS_TR session_handle = ESYS_TR_PASSWORD;
    ESYS_TR nv_result_handle;
    TPM2B_NV_PUBLIC public_info = {.size = 0};
    TPM2B_AUTH nv_auth = {.size = 0};

    public_info.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH) +
                       sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);

    /* Index of counter we want to allocate */
    public_info.nvPublic.nvIndex = index_handle;

    /* ??? */
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;

    /* Counter is 8 bytes, so allocate 8 bytes of space */
    public_info.nvPublic.dataSize = 8;

    // Now set the attributes.
    // ownerwrite|authwrite|nt=0x1|ownerread|authread|written
    // NOTE: tpm2_nvlist shows the attributes of this as 0x16000620
    // whereas we need to pass in 0x60016 to this API.
    // Now that is confusing!
    // public_info.nvPublic.attributes = 0x16000620;
    public_info.nvPublic.attributes = 0x60016;

    rc_return = Esys_NV_DefineSpace(
        g_esys_context,
        auth_handle,
        session_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_auth,
        &public_info,
        &nv_result_handle);
    if (rc_return != TPM2_RC_SUCCESS)
    {
        printf(
            "Failed(%u): Esys_NV_DefineSpace, failed to define index space\n",
            rc_return);
        return_value = -1;
    }
    return return_value;
}

// Increment the specified NV counter. Works only on nv counters and
// not other NV defined allocations.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_increment_nv_counter()
{
    int return_value = 0;
    uint32_t index_handle = TPM_COUNTER_ID;
    TSS2_RC rc_return;
    ESYS_TR nv_index;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    ESYS_TR session_handle = ESYS_TR_PASSWORD;

    rc_return = Esys_TR_FromTPMPublic(
        g_esys_context,
        index_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_index);
    if (rc_return != TPM2_RC_SUCCESS)
    {
        printf(
            "Failed(%u): Esys_TR_FromTPMPublic, Not a valid NV index (0x%X)?\n",
            rc_return,
            index_handle);
        return_value = -1;
    }
    else
    {
        rc_return = Esys_NV_Increment(
            g_esys_context,
            auth_handle,
            nv_index,
            session_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE);
        if (rc_return != TPM2_RC_SUCCESS)
        {
            printf(
                "Failed(%u): Esys_NV_Increment, Not a valid NV index, or not a "
                "counter (0x%X)?\n",
                rc_return,
                index_handle);
            return_value = -1;
        }
    }

    return return_value;
}

// Read the specified NV counter.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_read_nv_counter()
{
    int return_value = 0;
    uint32_t index_handle = TPM_COUNTER_ID;
    TSS2_RC rc_return;
    ESYS_TR nv_index;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    ESYS_TR session_handle = ESYS_TR_PASSWORD;

    rc_return = Esys_TR_FromTPMPublic(
        g_esys_context,
        index_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_index);
    if (rc_return != TPM2_RC_SUCCESS)
    {
        printf(
            "Failed(%u): Esys_TR_FromTPMPublic, Not a valid NV index (0x%X)?\n",
            rc_return,
            index_handle);
        return_value = -1;
    }
    else
    {
        TPM2B_MAX_NV_BUFFER* data;
        // Counter is 8 bytes, offset 0
        rc_return = Esys_NV_Read(
            g_esys_context,
            auth_handle,
            nv_index,
            session_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            8,
            0,
            &data);
        if (rc_return != TPM2_RC_SUCCESS)
        {
            printf(
                "Failed(%u): Esys_NV_Read, Not a valid NV index, or not a "
                "counter "
                "(0x%X)?\n",
                rc_return,
                index_handle);
            return_value = -1;
        }
        else
        {
            // Hey, lets print out the counter value!
            printf("Lets print out the counter!");
        }
    }
    return return_value;
}

int tpm_delete_nv_counter()
{
    int return_value = 0;
    uint32_t index_handle = TPM_COUNTER_ID;
    TSS2_RC rc_return;
    ESYS_TR nv_index;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    ESYS_TR session_handle = ESYS_TR_PASSWORD;

    rc_return = Esys_TR_FromTPMPublic(
        g_esys_context,
        index_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_index);
    if (rc_return != TPM2_RC_SUCCESS)
    {
        printf(
            "Failed(%u): Esys_TR_FromTPMPublic, Not a valid NV index (0x%X)?\n",
            rc_return,
            index_handle);
        return_value = -1;
    }
    else
    {
        rc_return = Esys_NV_UndefineSpace(
            g_esys_context,
            auth_handle,
            nv_index,
            session_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE);
        if (rc_return != TPM2_RC_SUCCESS)
        {
            printf(
                "Failed(%u): Esys_NV_UndefineSpace, Not a valid NV index, or "
                "not a counter (0x%X)?\n",
                rc_return,
                index_handle);
            return_value = -1;
        }
    }

    return return_value;
}
// Enumerate all NV indexes and print some information about them
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_list_nv_indexes()
{
    int return_value = 0;
    TSS2_RC rc_return;

    TPMS_CAPABILITY_DATA* capabilityData;
    rc_return = Esys_GetCapability(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_HANDLES,
        tpm2_util_hton_32(TPM2_HT_NV_INDEX),
        TPM2_PT_NV_INDEX_MAX,
        NULL,
        &capabilityData);
    if (rc_return == TSS2_RC_SUCCESS)
    {
        printf(
            "Succeeded: Esys_GetCapability, Number of used NV Indexes = %u\n",
            capabilityData->data.handles.count);
        UINT32 i;
        for (i = 0; i < capabilityData->data.handles.count; i++)
        {
            TPMI_RH_NV_INDEX index = capabilityData->data.handles.handle[i];
            ESYS_TR tr_object;
            rc_return = Esys_TR_FromTPMPublic(
                g_esys_context,
                index,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &tr_object);
            if (rc_return == TSS2_RC_SUCCESS)
            {
                TPM2B_NV_PUBLIC* nv_public;
                rc_return = Esys_NV_ReadPublic(
                    g_esys_context,
                    tr_object,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &nv_public,
                    NULL);
                if (rc_return == TSS2_RC_SUCCESS)
                {
                    printf(
                        "NV_Index=0x%X Algorithm=0x%hX Flags=0x%X\n",
                        index,
                        nv_public->nvPublic.nameAlg,
                        nv_public->nvPublic.attributes);

                    free(nv_public);
                }
                else
                {
                    printf("Failed(%u): Esys_NV_ReadPublic\n", rc_return);
                    return_value = -1;
                }

                rc_return = Esys_TR_Close(g_esys_context, &tr_object);
                if (rc_return == TSS2_RC_SUCCESS)
                {
                    printf("Succeeded: Esys_TR_Close\n");
                }
                else
                {
                    printf("Failed(%u): Esys_TR_Close\n", rc_return);
                    return_value = -1;
                }
            }
            else
            {
                printf("Failed(%u): Esys_TR_FromTPMPublic\n", rc_return);
                return_value = -1;
            }
        }
    }
    else
    {
        printf(
            "Failed(%u): Esys_GetCapability, failed to get max number of NV "
            "indexes\n",
            rc_return);
        return_value = -1;
    }

    return return_value;
}

// Get TPM relative time since last reboot?
// NOt using a secure session!
int tpm_get_time()
{
    int return_value = 0;
    TSS2_RC r;
    ESYS_TR signHandle = ESYS_TR_NONE;
    //    int failure_return = EXIT_FAILURE;

    TPM2B_AUTH authValuePrimary = {.size = 5, .buffer = {1, 2, 3, 4, 5}};

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive =
            {
                .userAuth =
                    {
                        .size = 0,
                        .buffer = {0},
                    },
                .data =
                    {
                        .size = 0,
                        .buffer = {0},
                    },
            },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea =
            {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes =
                    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                     TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
                     TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
                .authPolicy =
                    {
                        .size = 0,
                    },
                .parameters.rsaDetail =
                    {
                        .symmetric =
                            {
                                .algorithm = TPM2_ALG_NULL,
                                .keyBits.aes = 128,
                                .mode.aes = TPM2_ALG_CFB,
                            },
                        .scheme =
                            {
                                .scheme = TPM2_ALG_RSASSA,
                                .details = {.rsassa = {.hashAlg =
                                                           TPM2_ALG_SHA1}},

                            },
                        .keyBits = 2048,
                        .exponent = 0,
                    },
                .unique.rsa =
                    {
                        .size = 0,
                        .buffer = {},
                    },
            },
    };

    TPM2B_AUTH authValue = {.size = 0, .buffer = {}};

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    // LOG_INFO("\nRSA key will be created.");

    r = Esys_TR_SetAuth(g_esys_context, ESYS_TR_RH_OWNER, &authValue);
    // goto_if_error(r, "Error: TR_SetAuth", error);

    // RSRC_NODE_T* primaryHandle_node;
    TPM2B_PUBLIC* outPublic;
    TPM2B_CREATION_DATA* creationData;
    TPM2B_DIGEST* creationHash;
    TPMT_TK_CREATION* creationTicket;

    r = Esys_CreatePrimary(
        g_esys_context,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitivePrimary,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &signHandle,
        &outPublic,
        &creationData,
        &creationHash,
        &creationTicket);
    // goto_if_error(r, "Error esys create primary", error);

    // r = esys_GetResourceObject(g_esys_context, signHandle,
    // &primaryHandle_node); goto_if_error(r, "Error Esys GetResourceObject",
    // error);

    // LOG_INFO(
    //    "Created Primary with handle 0x%08x...",
    //    primaryHandle_node->rsrc.handle);

    r = Esys_TR_SetAuth(g_esys_context, signHandle, &authValuePrimary);
    // goto_if_error(r, "Error: TR_SetAuth", error);

    ESYS_TR privacyAdminHandle = ESYS_TR_RH_ENDORSEMENT;
    TPMT_SIG_SCHEME inScheme = {.scheme = TPM2_ALG_NULL};
    TPM2B_DATA qualifyingData = {0};
    TPM2B_ATTEST* timeInfo;
    TPMT_SIGNATURE* signature;

    r = Esys_GetTime(
        g_esys_context,
        privacyAdminHandle,
        signHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        &timeInfo,
        &signature);
    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER)))
    {
        //    LOG_WARNING("Command TPM2_GetTime not supported by TPM.");
        r = Esys_FlushContext(g_esys_context, signHandle);
        //    goto_if_error(r, "Flushing context", error);

        signHandle = ESYS_TR_NONE;
        //        failure_return = EXIT_SKIP;
        goto error;
    }
    // goto_if_error(r, "Error: GetTime", error);

    r = Esys_FlushContext(g_esys_context, signHandle);
    // goto_if_error(r, "Error: FlushContext", error);

    return EXIT_SUCCESS;

error:

    if (signHandle != ESYS_TR_NONE)
    {
        if (Esys_FlushContext(g_esys_context, signHandle) != TSS2_RC_SUCCESS)
        {
            // LOG_ERROR("Cleanup signHandle failed.");
        }
    }
    return return_value;
}

// Get some capabilities from the TPM using a session that protects
// the data such that the enclave host cannot see the data that is
// being passed back and forth between the enclave and the TPM.
int tpm_session_get_capabilities()
{
    int return_value = 0;
    TSS2_RC rc_return;
    ESYS_TR auth_session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_XOR,
                              .keyBits = {.exclusiveOr = TPM2_ALG_SHA1},
                              .mode = {.aes = TPM2_ALG_CFB}};
    TPMS_CAPABILITY_DATA* capabilityData;

    rc_return = Esys_StartAuthSession(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL,
        TPM2_SE_HMAC,
        &symmetric,
        TPM2_ALG_SHA1,
        &auth_session);
    if (rc_return == TSS2_RC_SUCCESS)
    {
        rc_return = Esys_TRSess_SetAttributes(
            g_esys_context,
            auth_session,
            TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT,
            TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT);
        if (rc_return == TSS2_RC_SUCCESS)
        {
            rc_return = Esys_GetCapability(
                g_esys_context,
                auth_session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                TPM2_CAP_HANDLES,
                tpm2_util_hton_32(TPM2_HT_NV_INDEX),
                TPM2_PT_NV_INDEX_MAX,
                NULL,
                &capabilityData);
            if (rc_return == TSS2_RC_SUCCESS)
            {
                printf(
                    "Succeeded: Esys_GetCapability, handle count=%u\n",
                    capabilityData->data.handles.count);
            }
            else
            {
                printf(
                    "Failed(%u): Esys_GetCapability, failed to get max number "
                    "of NV "
                    "indexes\n",
                    rc_return);
                return_value = -1;
            }
        }
        else
        {
            printf(
                "Failed(%u): Esys_TRSess_SetAttributes, failed to set session "
                "attributes\n",
                rc_return);
            return_value = -1;
        }

        rc_return = Esys_FlushContext(g_esys_context, auth_session);
        if (rc_return != TSS2_RC_SUCCESS)
        {
            printf("Failed(%u): Esys_FlushContext failed]n", rc_return);
            return_value = -1;
        }
    }
    else
    {
        printf(
            "Failed(%u): Esys_StartAuthSession, failed to initialize session",
            rc_return);
        return_value = -1;
    }

    return return_value;
}

int run_tpm_tests()
{
    int return_value;

    printf("\nRunning tpm_initialize...\n");
    return_value = tpm_initialize();
    if (return_value == 0)
    {
        printf("\nRunning get_capabilities...\n");
        return_value = tpm_get_capabilities();
        printf("\nRunning get_time...\n");
        return_value = tpm_get_time();

        printf("\nRunning list_nv_indexes...\n");
        return_value = tpm_list_nv_indexes();

        printf("\nRunning allocate_nv_counter...\n");
        return_value = tpm_allocate_nv_counter();
        if (return_value == 0)
        {
            printf("\nRunning list_nv_indexes...\n");
            return_value = tpm_list_nv_indexes();

            printf("\nRunning increment_nv_counter...\n");
            return_value = tpm_increment_nv_counter();

            printf("\nRunning read_nv_counter...\n");
            return_value = tpm_read_nv_counter();

            printf("\nRunning delete_nv_counter...\n");
            return_value = tpm_delete_nv_counter();
        }
        else
        {
            printf(
                "\nSkipping rest of NV tests due to NV allocation failure\n");
        }

        printf("\nRunning session-based get_capabilities...\n");
        return_value = tpm_session_get_capabilities();

        printf("\nRunning tpm_deinitialize...\n");
        return_value = tpm_deinitialize();
    }
}