// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Function to write an Offline Dump.
*/

#ifndef _included_Library_OfflineDumpWriterLib_h
#define _included_Library_OfflineDumpWriterLib_h

#include <Uefi/UefiBaseType.h>
#include <Protocol/OfflineDumpProvider.h>

/**
Writes an offline dump using information from the specified provider.

Static-link with this function to write an offline dump.

Alternatively, invoke OfflineDumpWrite.efi as an application using one of
the OfflineDumpWriteExecutePath or OfflineDumpWriteExecuteMemory functions.

General process:

- Validate protocol fields. Return EFI_UNSUPPORTED if invalid or out of range.
- Call pProvider->Begin(...). If it returns an error, return that error.
- Validate the dump information returned by Begin. If valid, write a dump.
- Call pProvider->End(Status) and then return Status.

Notes:

- OfflineDumpWrite may return an error without calling either Begin or End.
- If Begin returns an error, OfflineDumpWrite will immediately return that error
  without calling End.
- If Begin returns EFI_SUCCESS, OfflineDumpWrite will always call End(Status) and
  will return the same Status as it passed to End.

Consumes:

  BaseLib
  BaseMemoryLib
  DebugLib
  MemoryAllocationLib
  SynchronizationLib
  UefiBootServicesTableLib

  BaseCryptLib
  OpensslLib
**/
EFI_STATUS
OfflineDumpWrite (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL const  *pProvider
);

#endif // _included_Library_OfflineDumpWriterLib_h
