// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2_esys.h>
#include <tss2_rc.h>

#define test_starting(running_in_enclave, test)                                \
    {                                                                          \
        printf("\n***********************************************************" \
               "***************\n");                                           \
        printf(                                                                \
            "** Running[%s]: %s\n",                                            \
            running_in_enclave ? "enclave" : "host",                           \
            test);                                                             \
    }

#define test_finished(_return_code, running_in_enclave, test, error_label)     \
    if (_return_code != 0)                                                     \
    {                                                                          \
        printf(                                                                \
            "** Failed[%s]: %s\n",                                             \
            running_in_enclave ? "enclave" : "host",                           \
            test);                                                             \
        printf("*************************************************************" \
               "*************\n");                                             \
        return_value = (_return_code);                                         \
        goto error_label;                                                      \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        printf(                                                                \
            "** Passed[%s]: %s\n",                                             \
            running_in_enclave ? "enclave" : "host",                           \
            test);                                                             \
        printf("*************************************************************" \
               "*************\n");                                             \
    }

#define run_test(running_in_enclave, test, error_label)                \
    {                                                                  \
        test_starting(running_in_enclave, #test);                      \
        test_finished(test(), running_in_enclave, #test, error_label); \
    }

#define run_test_with_seal_key(                                         \
    running_in_enclave, test, seal_key, seal_key_size, error_label)     \
    {                                                                   \
        test_starting(running_in_enclave, #test);                       \
        int _result = test(seal_key, seal_key_size);                    \
        test_finished(_result, running_in_enclave, #test, error_label); \
    }

#define goto_if_tss_error(rc_return, msg, label)                             \
    if (rc_return != TSS2_RC_SUCCESS)                                        \
    {                                                                        \
        printf("%s, 0x%X, %s\n", msg, rc_return, Tss2_RC_Decode(rc_return)); \
        goto label;                                                          \
    }

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

static const char* algorithm_to_string(TPMI_ALG_HASH algorithm)
{
    switch (algorithm)
    {
        case TPM2_ALG_ERROR:
            return "TPM2_ALG_ERROR";
        case TPM2_ALG_RSA:
            return "TPM2_ALG_RSA";
        case TPM2_ALG_SHA1:
            return "TPM2_ALG_SHA1 or TPM2_ALG_SHA";
        case TPM2_ALG_HMAC:
            return "TPM2_ALG_HMAC";
        case TPM2_ALG_AES:
            return "TPM2_ALG_AES";
        case TPM2_ALG_MGF1:
            return "TPM2_ALG_MGF1";
        case TPM2_ALG_KEYEDHASH:
            return "TPM2_ALG_KEYEDHASH";
        case TPM2_ALG_XOR:
            return "TPM2_ALG_XOR";
        case TPM2_ALG_SHA256:
            return "TPM2_ALG_SHA256";
        case TPM2_ALG_SHA384:
            return "TPM2_ALG_SHA384";
        case TPM2_ALG_SHA512:
            return "TPM2_ALG_SHA512";
        case TPM2_ALG_NULL:
            return "TPM2_ALG_NULL";
        case TPM2_ALG_SM3_256:
            return "TPM2_ALG_SM3_256";
        case TPM2_ALG_SM4:
            return "TPM2_ALG_SM4";
        case TPM2_ALG_RSASSA:
            return "TPM2_ALG_RSASSA";
        case TPM2_ALG_RSAES:
            return "TPM2_ALG_RSAES";
        case TPM2_ALG_RSAPSS:
            return "TPM2_ALG_RSAPSS";
        case TPM2_ALG_OAEP:
            return "TPM2_ALG_OAEP";
        case TPM2_ALG_ECDSA:
            return "TPM2_ALG_ECDSA";
        case TPM2_ALG_ECDH:
            return "TPM2_ALG_ECDH";
        case TPM2_ALG_ECDAA:
            return "TPM2_ALG_ECDAA";
        case TPM2_ALG_SM2:
            return "TPM2_ALG_SM2";
        case TPM2_ALG_ECSCHNORR:
            return "TPM2_ALG_ECSCHNORR";
        case TPM2_ALG_ECMQV:
            return "TPM2_ALG_ECMQV";
        case TPM2_ALG_KDF1_SP800_56A:
            return "TPM2_ALG_KDF1_SP800_56A";
        case TPM2_ALG_KDF2:
            return "TPM2_ALG_KDF2";
        case TPM2_ALG_KDF1_SP800_108:
            return "TPM2_ALG_KDF1_SP800_108";
        case TPM2_ALG_ECC:
            return "TPM2_ALG_ECC";
        case TPM2_ALG_SYMCIPHER:
            return "TPM2_ALG_SYMCIPHER";
        case TPM2_ALG_CAMELLIA:
            return "TPM2_ALG_CAMELLIA";
        case TPM2_ALG_CTR:
            return "TPM2_ALG_CTR";
        case TPM2_ALG_SHA3_256:
            return "TPM2_ALG_SHA3_256";
        case TPM2_ALG_SHA3_384:
            return "TPM2_ALG_SHA3_384";
        case TPM2_ALG_OFB:
            return "TPM2_ALG_OFB";
        case TPM2_ALG_CBC:
            return "TPM2_ALG_CBC";
        case TPM2_ALG_CFB:
            return "TPM2_ALG_CFB";
        case TPM2_ALG_ECB:
            return "TPM2_ALG_ECB";
        default:
            return "<unknown/invalid>";
    }
}

static char* nv_attributes_to_string(TPMA_NV attributes)
{
    static char buffer[1000];

    buffer[0] = '\0';

    if (attributes & TPMA_NV_PPWRITE)
    {
        strcat(buffer, "TPMA_NV_PPWRITE ");
    }
    if (attributes & TPMA_NV_OWNERWRITE)
    {
        strcat(buffer, "TPMA_NV_OWNERWRITE ");
    }
    if (attributes & TPMA_NV_AUTHWRITE)
    {
        strcat(buffer, "TPMA_NV_AUTHWRITE ");
    }
    if (attributes & TPMA_NV_POLICYWRITE)
    {
        strcat(buffer, "TPMA_NV_POLICYWRITE ");
    }
    if (attributes & TPMA_NV_POLICY_DELETE)
    {
        strcat(buffer, "TPMA_NV_POLICY_DELETE ");
    }
    if (attributes & TPMA_NV_WRITELOCKED)
    {
        strcat(buffer, "TPMA_NV_WRITELOCKED ");
    }
    if (attributes & TPMA_NV_WRITEALL)
    {
        strcat(buffer, "TPMA_NV_WRITEALL ");
    }
    if (attributes & TPMA_NV_WRITEDEFINE)
    {
        strcat(buffer, "TPMA_NV_WRITEDEFINE ");
    }
    if (attributes & TPMA_NV_WRITE_STCLEAR)
    {
        strcat(buffer, "TPMA_NV_WRITE_STCLEAR ");
    }
    if (attributes & TPMA_NV_GLOBALLOCK)
    {
        strcat(buffer, "TPMA_NV_GLOBALLOCK ");
    }
    if (attributes & TPMA_NV_PPREAD)
    {
        strcat(buffer, "TPMA_NV_PPREAD ");
    }
    if (attributes & TPMA_NV_OWNERREAD)
    {
        strcat(buffer, "TPMA_NV_OWNERREAD ");
    }
    if (attributes & TPMA_NV_AUTHREAD)
    {
        strcat(buffer, "TPMA_NV_AUTHREAD ");
    }
    if (attributes & TPMA_NV_POLICYREAD)
    {
        strcat(buffer, "TPMA_NV_POLICYREAD ");
    }
    if (attributes & TPMA_NV_RESERVED2_MASK)
    {
        strcat(buffer, "TPMA_NV_RESERVED2_MASK ");
    }
    if (attributes & TPMA_NV_NO_DA)
    {
        strcat(buffer, "TPMA_NV_NO_DA ");
    }
    if (attributes & TPMA_NV_ORDERLY)
    {
        strcat(buffer, "TPMA_NV_ORDERLY ");
    }
    if (attributes & TPMA_NV_CLEAR_STCLEAR)
    {
        strcat(buffer, "TPMA_NV_CLEAR_STCLEAR ");
    }
    if (attributes & TPMA_NV_READLOCKED)
    {
        strcat(buffer, "TPMA_NV_READLOCKED ");
    }
    if (attributes & TPMA_NV_WRITTEN)
    {
        strcat(buffer, "TPMA_NV_WRITTEN ");
    }
    if (attributes & TPMA_NV_PLATFORMCREATE)
    {
        strcat(buffer, "TPMA_NV_PLATFORMCREATE ");
    }
    if (attributes & TPMA_NV_READ_STCLEAR)
    {
        strcat(buffer, "TPMA_NV_READ_STCLEAR ");
    }
    switch (attributes & TPMA_NV_TPM2_NT_MASK)
    {
        case (TPM2_NT_ORDINARY << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_COUNTER ");
            break;
        }
        case (TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_COUNTER ");
            break;
        }
        case (TPM2_NT_BITS << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_BITS ");
            break;
        }
        case (TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_EXTEND ");
            break;
        }
        case (TPM2_NT_PIN_FAIL << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_PIN_FAIL ");
            break;
        }
        case (TPM2_NT_PIN_PASS << TPMA_NV_TPM2_NT_SHIFT):
        {
            strcat(buffer, "TPM2_NT_PIN_PASS ");
            break;
        }
    }
    return buffer;
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
    return 0;
}

// get_capabilities is more just a validation that we can actually talk
// to the TPM. In this case it is associated with number of NV Indexes,
// but could have been anything.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_get_capabilities()
{
    int return_value = -1;
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

    goto_if_tss_error(
        rc_return,
        "Esys_GetCapability, failed to get max number of NV indexes",
        error);

    printf(
        "Succeeded: Esys_GetCapability, Number of used NV Indexes = %u\n",
        capabilityData->data.handles.count);

    Esys_Free(capabilityData);

    return_value = 0;

error:
    return return_value;
}

// allocate_nv_counter calls into the TPM to allocate a 8-byte counter
// giving it the index passed in.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_allocate_nv_counter()
{
    int return_value = -1;
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
    public_info.nvPublic.attributes =
        (TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE | TPMA_NV_OWNERREAD |
         TPMA_NV_AUTHREAD | TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT);

    rc_return = Esys_NV_DefineSpace(
        g_esys_context,
        auth_handle,
        session_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_auth,
        &public_info,
        &nv_result_handle);

    goto_if_tss_error(
        rc_return, "Esys_NV_DefineSpace, failed to define index space", error);

    return_value = 0;

error:
    return return_value;
}

// Increment the specified NV counter. Works only on nv counters and
// not other NV defined allocations.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_increment_nv_counter()
{
    int return_value = -1;
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

    goto_if_tss_error(
        rc_return, "Esys_NV_DefineSpace, failed to define index space", error);

    rc_return = Esys_NV_Increment(
        g_esys_context,
        auth_handle,
        nv_index,
        session_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE);

    goto_if_tss_error(
        rc_return,
        "Esys_NV_Increment, Not a valid NV index, or not a counter",
        error);

    return_value = 0;

error:
    return return_value;
}

// Read the specified NV counter.
// This is not using an encrypted session so the host can see and
// potentially tamper with the data that we receive.
int tpm_read_nv_counter()
{
    int return_value = 0;
    uint32_t index = TPM_COUNTER_ID;
    TSS2_RC rc_return;
    ESYS_TR tr_object;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    ESYS_TR session_handle = ESYS_TR_PASSWORD;

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
            TPM2B_MAX_NV_BUFFER* data;
            rc_return = Esys_NV_Read(
                g_esys_context,
                auth_handle,
                tr_object,
                session_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                nv_public->nvPublic.dataSize,
                0,
                &data);
            if (rc_return != TPM2_RC_SUCCESS)
            {
                printf(
                    "Failed(%u): Esys_NV_Read, Not a valid NV index, or not a "
                    "counter "
                    "(0x%X)?\n",
                    rc_return,
                    index);
                return_value = -1;
            }
            else
            {
                printf(
                    "NV_Index=0x%X\n"
                    "\tAlgorithm=%s (0x%hX)\n"
                    "\tAttributes=%s (0x%X)\n",
                    index,
                    algorithm_to_string(nv_public->nvPublic.nameAlg),
                    nv_public->nvPublic.nameAlg,
                    nv_attributes_to_string(nv_public->nvPublic.attributes),
                    nv_public->nvPublic.attributes);

                printf("\tSize=%u BYTES\n", data->size);
                printf("\tData=<");
                for (int i = 0; i != data->size; i++)
                {
                    printf("%02x", data->buffer[i]);
                }
                printf(">\n");
                Esys_Free(data);
            }

            Esys_Free(nv_public);
        }
        else
        {
            printf("Failed(%u): Esys_NV_ReadPublic\n", rc_return);
            return_value = -1;
        }

        rc_return = Esys_TR_Close(g_esys_context, &tr_object);
        if (rc_return != TSS2_RC_SUCCESS)
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
                        "NV_Index=0x%X\n"
                        "\tdataSize=0x%X\n"
                        "\tAlgorithm=%s (0x%hX)\n"
                        "\tAttributes=%s (0x%X)\n"
                        "\tAuthorization policy length=0x%X\n",
                        index,
                        nv_public->nvPublic.dataSize,
                        algorithm_to_string(nv_public->nvPublic.nameAlg),
                        nv_public->nvPublic.nameAlg,
                        nv_attributes_to_string(nv_public->nvPublic.attributes),
                        nv_public->nvPublic.attributes,
                        nv_public->nvPublic.authPolicy.size);

                    Esys_Free(nv_public);
                }
                else
                {
                    printf("Failed(%u): Esys_NV_ReadPublic\n", rc_return);
                    return_value = -1;
                }

                rc_return = Esys_TR_Close(g_esys_context, &tr_object);
                if (rc_return != TSS2_RC_SUCCESS)
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

        Esys_Free(capabilityData);
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
    TSS2_RC rc_return;
    TPMS_TIME_INFO* currentTime;

    rc_return = Esys_ReadClock(
        g_esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &currentTime);

    if ((rc_return == TPM2_RC_COMMAND_CODE) ||
        (rc_return == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (rc_return == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER)))
    {
        printf("Esys_ReadClock not supported? 0x%X\n", rc_return);
        return_value = -1;
    }
    else if (rc_return != TSS2_RC_SUCCESS)
    {
        printf("Esys_ReadClock failed 0x%X\n", rc_return);
        return_value = -1;
    }
    else
    {
        printf(
            "Clock=0x%" PRIx64 ", resetCount=0x%" PRIx32
            ", restartCount=0x%" PRIx32 ", safe=%s, time=0x%" PRIx64 "\n",
            currentTime->clockInfo.clock,
            currentTime->clockInfo.resetCount,
            currentTime->clockInfo.restartCount,
            (currentTime->clockInfo.safe == TPM2_YES ? "Yes" : "No"),
            currentTime->time);
#if 0
        UINT64 clock; /* time in milliseconds during which the TPM has been
                        powered. This structure element is used to report on
                        the TPMs Clock value. The value of Clock shall be
                        recorded in nonvolatile memory no less often than once
                        per 69.9 minutes, 222 milliseconds of TPM operation.
                        The reference for the millisecond timer is the TPM
                        oscillator. This value is reset to zero when the
                        Storage Primary Seed is changed TPM2_Clear. This value
                        may be advanced by TPM2_AdvanceClock. */
        UINT32 resetCount;   /* number of occurrences of TPM Reset since the
                                last TPM2_Clear */
        UINT32 restartCount; /* number of times that TPM2_Shutdown or
                                _TPM_Hash_Start have occurred since the last
                                TPM Reset or TPM2_Clear. */
        TPMI_YES_NO safe;    /* no value of Clock greater than the current
                                value of Clock has been previously reported by
                                the TPM. Set to YES on TPM2_Clear. */
    UINT64 time;               /* time in milliseconds since the last _TPM_Init or 
                                TPM2_Startup. This structure element is used to report on the TPMs Time value. */
#endif

        Esys_Free(currentTime);
    }

    return return_value;
}

// Test an operation using an encrypted session
int tpm_encrypted_session(uint8_t* seal_key, size_t seal_key_size)
{
    TSS2_RC rc_return;
    int return_value = 0;
    ESYS_TR nv_handle = ESYS_TR_NONE;
    ESYS_TR session_enc = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}};

    // Note! This is really bad! The nonce should be random to ensure
    // freshness of hte session
    TPM2B_NONCE nonce_caller = {
        .size = 20, .buffer = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                               11, 12, 13, 14, 15, 16, 17, 18, 19, 20}};

    /* Enc param session */
    rc_return = Esys_StartAuthSession(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonce_caller,
        TPM2_SE_HMAC,
        &symmetric,
        TPM2_ALG_SHA1,
        &session_enc);
    goto_if_tss_error(
        rc_return, "Error: During initialization of session_enc", error);

    /* Set both ENC and DEC flags for the enc session */
    TPMA_SESSION session_attributes = TPMA_SESSION_DECRYPT |
                                      TPMA_SESSION_ENCRYPT |
                                      TPMA_SESSION_CONTINUESESSION;

    rc_return = Esys_TRSess_SetAttributes(
        g_esys_context, session_enc, session_attributes, 0xFF);
    goto_if_tss_error(rc_return, "Error: During SetAttributes", error);

    TPM2B_AUTH auth = {.size = 0, .buffer = {0}};
    if (seal_key_size && seal_key)
    {
        if (seal_key_size > 64)
        {
            printf("Error: seal key is too long!\n");
            return_value = -1;
            goto error;
        }
        auth.size = seal_key_size;
        memcpy(auth.buffer, seal_key, seal_key_size);
        printf("Seal key has been set\n");
    }

    TPM2B_NV_PUBLIC public_info = {
        .size = 0,
        .nvPublic = {
            .nvIndex = TPM_COUNTER_ID,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes =
                (TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE | TPMA_NV_OWNERREAD |
                 TPMA_NV_AUTHREAD | TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy =
                {
                    .size = 0,
                    .buffer = {},
                },
            .dataSize = 8,
        }};

    rc_return = Esys_NV_DefineSpace(
        g_esys_context,
        ESYS_TR_RH_OWNER,
        session_enc,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &auth,
        &public_info,
        &nv_handle);
    goto_if_tss_error(rc_return, "Error esys define nv space", error);

    rc_return = Esys_NV_Increment(
        g_esys_context,
        nv_handle,
        nv_handle,
        session_enc,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_if_tss_error(rc_return, "Error esys nv write", error);

    TPM2B_MAX_NV_BUFFER* data;

    // Read encrypted
    rc_return = Esys_NV_Read(
        g_esys_context,
        nv_handle,
        nv_handle,
        session_enc,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        8,
        0,
        &data);
    goto_if_tss_error(rc_return, "Error: nv read", error);

    printf("\nSecured index data:\n");
    printf("\tSize=%u BYTES\n", data->size);
    printf("\tData=<");
    for (int i = 0; i != data->size; i++)
    {
        printf("%02x", data->buffer[i]);
    }
    printf(">\n");

    Esys_Free(data);

    // List the indexes. Ours will be there
    printf("\nIndex enumeration:\n");
    tpm_list_nv_indexes();

    // Read the counter unencrypted. This works and the host will be
    // able to see what we are reading.
    // As there is no policy on the counter we are able to read it too.
    printf("\nRead NV counter\n");
    tpm_read_nv_counter();

error:
    if (rc_return)
        return_value = -1;

    if (nv_handle != ESYS_TR_NONE)
    {
        if (Esys_NV_UndefineSpace(
                g_esys_context,
                ESYS_TR_RH_OWNER,
                nv_handle,
                session_enc,
                ESYS_TR_NONE,
                ESYS_TR_NONE) != TSS2_RC_SUCCESS)
        {
            printf("Cleanup nv_handle failed.");
        }
    }

    if (session_enc != ESYS_TR_NONE)
    {
        if (Esys_FlushContext(g_esys_context, session_enc) != TSS2_RC_SUCCESS)
        {
            printf("Cleanup session_enc failed.");
        }
    }

    return return_value;
}

int tpm_policy_protected_session(uint8_t* seal_key, size_t seal_key_size)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR policySession = ESYS_TR_NONE;
    TPM2B_DIGEST* policyDigestTrial = NULL;
    TPM2B_PUBLIC* outPublic = NULL;
    TPM2B_CREATION_DATA* creationData = NULL;
    TPM2B_DIGEST* creationHash = NULL;
    TPMT_TK_CREATION* creationTicket = NULL;
    TPM2B_PUBLIC* outPublic2 = NULL;
    TPM2B_PRIVATE* outPrivate2 = NULL;
    TPM2B_CREATION_DATA* creationData2 = NULL;
    TPM2B_DIGEST* creationHash2 = NULL;
    TPMT_TK_CREATION* creationTicket2 = NULL;

    /*
     * Firth the policy value for changing the auth value of an NV index has to
     * be determined with a policy trial session.
     */
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_AES,
                                   .keyBits = {.aes = 128},
                                   .mode = {.aes = TPM2_ALG_CFB}};
    TPM2B_NONCE nonceCallerTrial = {
        .size = 20, .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                               21, 22, 23, 24, 25, 26, 27, 28, 29, 30}};

    r = Esys_StartAuthSession(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonceCallerTrial,
        TPM2_SE_TRIAL,
        &symmetricTrial,
        TPM2_ALG_SHA1,
        &sessionTrial);
    goto_if_tss_error(
        r, "Error: During initialization of policy trial session", error);

    r = Esys_PolicyPassword(
        g_esys_context, sessionTrial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_tss_error(r, "Error: PolicyPassword", error);

    r = Esys_PolicyGetDigest(
        g_esys_context,
        sessionTrial,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &policyDigestTrial);
    goto_if_tss_error(r, "Error: PolicyGetDigest", error);

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea =
            {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes =
                    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                     TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                     TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
                .authPolicy = *policyDigestTrial,
                .parameters.rsaDetail =
                    {
                        .symmetric = {.algorithm = TPM2_ALG_AES,
                                      .keyBits.aes = 128,
                                      .mode.aes = TPM2_ALG_CFB},
                        .scheme = {.scheme = TPM2_ALG_NULL},
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

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {.size = 0, .buffer = {}};

    r = Esys_TR_SetAuth(g_esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_tss_error(r, "Error: TR_SetAuth", error);

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
        &primaryHandle,
        &outPublic,
        &creationData,
        &creationHash,
        &creationTicket);
    goto_if_tss_error(r, "Error esys create primary", error);

    TPMT_SYM_DEF policySymmetric = {.algorithm = TPM2_ALG_AES,
                                    .keyBits = {.aes = 128},
                                    .mode = {.aes = TPM2_ALG_CFB}};
    TPM2B_NONCE policyNonceCaller = {
        .size = 20, .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                               21, 22, 23, 24, 25, 26, 27, 28, 29, 30}};
    r = Esys_StartAuthSession(
        g_esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &policyNonceCaller,
        TPM2_SE_POLICY,
        &policySymmetric,
        TPM2_ALG_SHA1,
        &policySession);
    goto_if_tss_error(
        r, "Error: During initialization of policy trial session", error);

    r = Esys_PolicyPassword(
        g_esys_context,
        policySession,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_if_tss_error(r, "Error: PolicyAuthValue", error);

    r = Esys_TR_SetAuth(g_esys_context, primaryHandle, &authValuePrimary);
    goto_if_tss_error(r, "Error: TR_SetAuth", error);

    TPM2B_AUTH authKey2 = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
        .sensitive = {.userAuth = authKey2, .data = {.size = 0, .buffer = {}}}};

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes =
                (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                 TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy =
                {
                    .size = 0,
                },
            .parameters.rsaDetail = {.symmetric = {.algorithm = TPM2_ALG_AES,
                                                   .keyBits.aes = 128,
                                                   .mode.aes = TPM2_ALG_CFB},
                                     .scheme =
                                         {
                                             .scheme = TPM2_ALG_NULL,
                                         },
                                     .keyBits = 2048,
                                     .exponent = 0},
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            }}};

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    r = Esys_Create(
        g_esys_context,
        primaryHandle,
        policySession,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitive2,
        &inPublic2,
        &outsideInfo2,
        &creationPCR2,
        &outPrivate2,
        &outPublic2,
        &creationData2,
        &creationHash2,
        &creationTicket2);
    goto_if_tss_error(r, "Error esys create ", error);

    r = Esys_FlushContext(g_esys_context, primaryHandle);
    goto_if_tss_error(r, "Error: FlushContext", error);

    r = Esys_FlushContext(g_esys_context, sessionTrial);
    goto_if_tss_error(r, "Flushing context", error);

    r = Esys_FlushContext(g_esys_context, policySession);
    goto_if_tss_error(r, "Flushing context", error);

    if (policyDigestTrial)
    {
        Esys_Free(policyDigestTrial);
    }
    if (outPublic)
    {
        Esys_Free(outPublic);
    }
    if (creationData)
    {
        Esys_Free(creationData);
    }
    if (creationHash)
    {
        Esys_Free(creationHash);
    }
    if (creationTicket)
    {
        Esys_Free(creationTicket);
    }

    if (outPublic2)
    {
        Esys_Free(outPublic2);
    }
    if (outPrivate2)
    {
        Esys_Free(outPrivate2);
    }
    if (creationData2)
    {
        Esys_Free(creationData2);
    }
    if (creationHash2)
    {
        Esys_Free(creationHash2);
    }
    if (creationTicket2)
    {
        Esys_Free(creationTicket2);
    }

    return EXIT_SUCCESS;

error:

    if (policySession != ESYS_TR_NONE)
    {
        if (Esys_FlushContext(g_esys_context, policySession) != TSS2_RC_SUCCESS)
        {
            printf("Cleanup policySession failed.");
        }
    }

    if (primaryHandle != ESYS_TR_NONE)
    {
        if (Esys_FlushContext(g_esys_context, primaryHandle) != TSS2_RC_SUCCESS)
        {
            printf("Cleanup primaryHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

// Pass in the seal key used for the encryption tests.
// Within enclave this should be the enclave sealing key.
// In the host this will be, well, something else!
int run_tpm_tests(
    bool running_in_enclave,
    uint8_t* seal_key,
    size_t seal_key_size)
{
    int return_value = 0;

    printf("\nStarting tpm_tests...\n");

    run_test(running_in_enclave, tpm_initialize, error_no_deinitialize);

    run_test(running_in_enclave, tpm_get_capabilities, error);

    run_test(running_in_enclave, tpm_get_time, error);

    run_test(running_in_enclave, tpm_list_nv_indexes, error);

    run_test(running_in_enclave, tpm_allocate_nv_counter, error);

    run_test(running_in_enclave, tpm_list_nv_indexes, error_delete_counter);

    run_test(
        running_in_enclave, tpm_increment_nv_counter, error_delete_counter);

    run_test(running_in_enclave, tpm_read_nv_counter, error_delete_counter);

    run_test(running_in_enclave, tpm_delete_nv_counter, error);

    run_test(running_in_enclave, tpm_list_nv_indexes, error);

    run_test_with_seal_key(
        running_in_enclave,
        tpm_encrypted_session,
        seal_key,
        seal_key_size,
        error);

    run_test_with_seal_key(
        running_in_enclave,
        tpm_policy_protected_session,
        seal_key,
        seal_key_size,
        error);

error:
    run_test(running_in_enclave, tpm_deinitialize, error);

error_no_deinitialize:
    printf("\nFinished tpm_tests...\n");

    return return_value;

error_delete_counter:
    run_test(running_in_enclave, tpm_delete_nv_counter, error);
    goto error;
}
