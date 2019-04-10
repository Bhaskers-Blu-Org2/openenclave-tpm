// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (rc_return != TPM2_RC_SUCCESS)
    {
        printf(
            "Failed(%u): Esys_NV_DefineSpace, failed to define index "
            "space\n",
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
            }

            free(nv_public);
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
                        "\tAttributes=%s (0x%X)\n",
                        index,
                        nv_public->nvPublic.dataSize,
                        algorithm_to_string(nv_public->nvPublic.nameAlg),
                        nv_public->nvPublic.nameAlg,
                        nv_attributes_to_string(nv_public->nvPublic.attributes),
                        nv_public->nvPublic.attributes);

                    free(nv_public);
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
    TPMS_TIME_INFO* currentTime;

    r = Esys_ReadClock(
        g_esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &currentTime);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER)))
    {
        printf("Esys_ReadClock not supported? 0x%X\n", r);
        return_value = -1;
    }
    else if (r != TSS2_RC_SUCCESS)
    {
        printf("Esys_ReadClock failed 0x%X\n", r);
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
                    "Succeeded: Esys_GetCapability, NV Index count=%u\n",
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

    return return_value;
}