/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */
/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved. */
#ifndef TCTI_TBS_OCALLS_H
#define TCTI_TBS_OCALLS_H

#include "ocall-tbs.h"
#include "tcti-common.h"

#define TCTI_TBS_MAGIC 0xfbf2afa3761e188aULL

typedef struct
{
    TSS2_TCTI_COMMON_CONTEXT common;
    void* hContext;
    PBYTE commandBuffer;
    UINT32 commandSize;
} TSS2_TCTI_TBS_CONTEXT;

TBS_RESULT Tbsip_Submit_Command(
    TBS_HCONTEXT hContext,
    TBS_COMMAND_LOCALITY Locality,
    TBS_COMMAND_PRIORITY Priority,
    PCBYTE pabCommand,
    UINT32 cbCommand,
    PBYTE pabResult,
    PUINT32 pcbResult);

TBS_RESULT Tbsip_Context_Close(TBS_HCONTEXT hContext);

TBS_RESULT Tbsip_Cancel_Commands(TBS_HCONTEXT hContext);

TBS_RESULT Tbsi_Context_Create(
    PCTBS_CONTEXT_PARAMS pContextParams,
    PTBS_HCONTEXT phContext);

TBS_RESULT Tbsi_GetDeviceInfo(UINT32 Size, PVOID Info);

#endif /* TCTI_TBS_H */
