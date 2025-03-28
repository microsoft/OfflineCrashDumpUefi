// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#ifndef _included_OfflineDumpSecureConfiguration_h
#define _included_OfflineDumpSecureConfiguration_h

#include <Protocol/OfflineDumpProvider.h>
#include "OfflineDumpRedactionMap.h"

BOOLEAN
OfflineDumpSecureConfiguration_MustRedactCpuContext (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  IN OFFLINE_DUMP_REDACTION_MAP const       *pMap,
  IN UINT32                                 CpuIndex
  );

EFI_STATUS
OfflineDumpSecureConfiguration_PrepareRedactionMap (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  OUT OFFLINE_DUMP_REDACTION_MAP            *pMap
  );

#endif // _included_OfflineDumpRedactionMap_h
