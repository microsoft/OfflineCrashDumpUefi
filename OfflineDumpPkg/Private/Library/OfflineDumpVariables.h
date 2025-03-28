// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Functions for reading Offline Dump firmware variables.

Consumes:
  MemoryAllocationLib       (AllocatePool)
  UefiBootServicesTableLib  (gST->RuntimeServices->GetVariable)
*/

#ifndef _included_OfflineDumpVariables_h
#define _included_OfflineDumpVariables_h

#include <Uefi/UefiBaseType.h>
#include <Guid/OfflineDumpConfig.h>
#include <Guid/OfflineDumpEncryption.h>

// Returns the value of the OfflineMemoryDumpUseCapability firmware variable.
EFI_STATUS
GetVariableOfflineMemoryDumpUseCapability (
  OUT OFFLINE_DUMP_USE_CAPABILITY_FLAGS  *pFlags
  );

// Returns the value of the OfflineMemoryDumpOsData firmware variable.
EFI_STATUS
GetVariableOfflineMemoryDumpOsData (
  OUT UINT64  *pOsData
  );

// Returns the value of the OfflineMemoryDumpEncryptionAlgorithm firmware variable.
EFI_STATUS
GetVariableOfflineMemoryDumpEncryptionAlgorithm (
  OUT ENC_DUMP_ALGORITHM  *pAlgorithm
  );

// Returns the value of the OfflineMemoryDumpEncryptionPublicKey firmware variable.
// The caller is responsible for freeing the RecipientCertificate via
// FreePool(*ppRecipientCertificate).
EFI_STATUS
GetVariableOfflineMemoryDumpEncryptionPublicKey (
  OUT void    **ppRecipientCertificate,
  OUT UINT32  *pRecipientCertificateSize
  );

#endif // _included_OfflineDumpVariables_h
