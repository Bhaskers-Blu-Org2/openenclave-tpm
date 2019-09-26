#ifndef OCALL_TBS_H
#define OCALL_TBS_H

#if defined(_MSC_VER)
/* Windows use the proper header file. Should only happen in a Windows host */
#include <tbs.h>
#include <windows.h>
#else /* _MSC_VER */
/* Linux Enclave defines all types needed to do ocall to a Windows host.
   If not a windows host then it is a no-op as it will not be called!
   */
#include <inttypes.h>

/* Stuff grabbed from windows tbs.h that is needed for this to build on Linux */
typedef uint8_t UINT8;
typedef uint8_t BYTE;
typedef int8_t INT8;
typedef int BOOL;
typedef uint16_t UINT16;
typedef int16_t INT16;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint64_t UINT64;
typedef int64_t INT64;

#define TBS_SUCCESS 0
#define TBS_COMMAND_LOCALITY_ZERO 0
#define TBS_COMMAND_PRIORITY_NORMAL 200
#define TPM_VERSION_20 2
#define TBS_CONTEXT_VERSION_TWO 2

typedef unsigned int* PUINT32;
typedef UINT32 TBS_RESULT;
typedef void* PVOID;
typedef UINT32 TBS_COMMAND_PRIORITY;
typedef PVOID TBS_HCONTEXT, *PTBS_HCONTEXT;
typedef UINT32 TBS_COMMAND_LOCALITY;
typedef BYTE* PBYTE;
typedef const BYTE* PCBYTE;

typedef struct
{
    UINT32 version;
    union {
        struct
        {
            UINT32 requestRaw : 1;
            UINT32 includeTpm12 : 1;
            UINT32 includeTpm20 : 1;
        };
        UINT32 asUINT32;
    };
} TBS_CONTEXT_PARAMS2, *PTBS_CONTEXT_PARAMS2;

typedef struct
{
    UINT32 structVersion;
    UINT32 tpmVersion;
    UINT32 tpmInterfaceType;
    UINT32 tpmImpRevision;
} TPM_DEVICE_INFO, *PTPM_DEVICE_INFO;

typedef struct
{
    UINT32 version;
} TBS_CONTEXT_PARAMS, *PTBS_CONTEXT_PARAMS;
typedef const TBS_CONTEXT_PARAMS* PCTBS_CONTEXT_PARAMS;

#endif /* _MSC_VER */

#endif /* OCALL_TBS_H */