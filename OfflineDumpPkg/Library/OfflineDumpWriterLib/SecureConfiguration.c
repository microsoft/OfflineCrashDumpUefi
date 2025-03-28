// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <Library/OfflineDumpSecureConfiguration.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include "SecureConfigurationArm64.h"

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

// If pDumpInfo->SecureCpuContext has a valid entry for CpuIndex,
// copy it to pSecureCpuContext and return TRUE.
static BOOLEAN
CopySecureCpuContext (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  IN UINT32                                 CpuIndex,
  IN UINT32                                 RequiredSize,
  OUT VOID                                  *pSecureCpuContext
  )
{
  if (CpuIndex >= pDumpInfo->SecureCpuContextCount) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "CpuIndex %u >= SecureCpuContextCount %u\n",
                 CpuIndex,
                 pDumpInfo->SecureCpuContextCount
                 );
    return FALSE;
  }

  if (pDumpInfo->SecureCpuContextSize < RequiredSize) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "SecureCpuContextSize provided %u < required %u\n",
                 pDumpInfo->SecureCpuContextSize,
                 RequiredSize
                 );
    return FALSE;
  }

  CopyMem (
           pSecureCpuContext,
           (UINT8 const *)pDumpInfo->pSecureCpuContexts + pDumpInfo->SecureCpuContextSize * CpuIndex,
           RequiredSize
           );
  return TRUE;
}

EFI_STATUS
OfflineDumpSecureConfiguration_PrepareRedactionMap (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  OUT OFFLINE_DUMP_REDACTION_MAP            *pMap
  )
{
  EFI_STATUS  Status;

  switch (pDumpInfo->Architecture) {
    case RAW_DUMP_ARCHITECTURE_ARM64:
      Status = OfflineDumpSecureConfigurationArm64_PrepareRedactionMap (pDumpInfo, pMap);
      break;

    default:
      DEBUG_PRINT (DEBUG_ERROR, "Unsupported Architecture %u\n", pDumpInfo->Architecture);
      Status = EFI_UNSUPPORTED;
      break;
  }

  return Status;
}

BOOLEAN
OfflineDumpSecureConfiguration_MustRedactCpuContext (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  IN OFFLINE_DUMP_REDACTION_MAP const       *pMap,
  IN UINT32                                 CpuIndex
  )
{
  BOOLEAN  MustRedact = TRUE; // If anything goes wrong, redact the CPU context.

  switch (pDumpInfo->Architecture) {
    case RAW_DUMP_ARCHITECTURE_ARM64:
    {
      OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64  SecureCpuContext;
      if (!CopySecureCpuContext (
                                 pDumpInfo,
                                 CpuIndex,
                                 sizeof (SecureCpuContext),
                                 &SecureCpuContext
                                 ))
      {
        goto Done;
      }

      MustRedact = OfflineDumpSecureConfigurationArm64_MustRedactCpuContext (pMap, &SecureCpuContext);
      break;
    }

    default:
      DEBUG_PRINT (DEBUG_ERROR, "Unsupported Architecture %u\n", pDumpInfo->Architecture);
      goto Done;
  }

Done:

  return MustRedact;
}
