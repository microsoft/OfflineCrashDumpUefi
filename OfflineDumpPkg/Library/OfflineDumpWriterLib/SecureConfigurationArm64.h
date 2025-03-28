// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#ifndef _included_SecureConfigurationArm64_h
#define _included_SecureConfigurationArm64_h

#include <Protocol/OfflineDumpProvider.h>
#include <Library/OfflineDumpRedactionMap.h>

EFI_STATUS
OfflineDumpSecureConfigurationArm64_PrepareRedactionMap (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  OUT OFFLINE_DUMP_REDACTION_MAP            *pMap
  );

BOOLEAN
OfflineDumpSecureConfigurationArm64_MustRedactCpuContext (
  IN OFFLINE_DUMP_REDACTION_MAP const                      *pMap,
  IN OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64 const  *pSecureCpuContext
  );

#endif // _included_SecureConfigurationArm64_h
