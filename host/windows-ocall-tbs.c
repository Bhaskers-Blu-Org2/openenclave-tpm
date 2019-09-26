#include "tpm_u.h"

TBS_RESULT ocall_Tbsip_Submit_Command(
    uint64_t hContext,
    uint32_t Locality,
    uint32_t Priority,
    const uint8_t* pabCommand,
    uint32_t cbCommand,
    int8_t* pabResult,
    uint32_t pabResult_length,
    uint32_t* pcbResult_used)
{
#if defined(_MSC_VER)
    TBS_RESULT result = Tbsip_Submit_Command(
        (TBS_HCONTEXT)hContext,
        (TBS_COMMAND_LOCALITY)Locality,
        (TBS_COMMAND_PRIORITY)Priority,
        (PCBYTE)pabCommand,
        cbCommand,
        pabResult,
        &pabResult_length);
    *pcbResult_used = pabResult_length;
    return result;
#else
    return 0;
#endif
}

TBS_RESULT ocall_Tbsip_Context_Close(uint64_t hContext)
{
#if defined(_MSC_VER)
    return Tbsip_Context_Close((TBS_HCONTEXT)hContext);
#else
    return 0;
#endif
}

TBS_RESULT ocall_Tbsip_Cancel_Commands(uint64_t hContext)
{
#if defined(_MSC_VER)
    return Tbsip_Cancel_Commands((TBS_HCONTEXT)hContext);
#else
    return 0;
#endif
}

TBS_RESULT ocall_Tbsi_Context_Create(
    PCTBS_CONTEXT_PARAMS pContextParams,
    uint64_t* phContext)
{
#if defined(_MSC_VER)
    return Tbsi_Context_Create(pContextParams, (TBS_HCONTEXT*)hContext);
#else
    return 0;
#endif
}

TBS_RESULT ocall_Tbsi_GetDeviceInfo(UINT32 Size, uint8_t* Info)
{
#if defined(_MSC_VER)
    return Tbsi_GetDeviceInfo(Size, (PVOID)Info);
#else
    return 0;
#endif
}
