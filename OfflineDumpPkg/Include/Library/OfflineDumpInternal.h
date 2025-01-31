/*
Microsoft Offline Dump - Internal functions for working with an Offline Dump.

The contents of this file are temporarily provided for a transition period.
Users should switch to using the binary OfflineDumpCollect.efi and launch it
via an OfflineDumpCollectExecute function instead of calling OfflineDumpCollect.
*/

#ifndef _included_Library_OfflineDumpInternal_h
#define _included_Library_OfflineDumpInternal_h

#include <Protocol/OfflineDumpProvider.h>

/**
Collects an offline dump using information from the specified provider.

IMPORTANT: This is a temporary placeholder and will soon be removed. Please use one of
the OfflineDumpCollectExecute functions to run the OfflineDumpCollect.efi app instead of
calling directly into this function.

General process:

- Validate protocol fields. Return EFI_UNSUPPORTED if invalid or out of range.
- Call pProvider->Begin(...). If it returns an error, return that error.
- Validate the dump information returned by Begin. If valid, write a dump.
- Call pProvider->End(Status) and then return Status.

Notes:

- OfflineDumpCollect may return an error without calling either Begin or End.
- If Begin returns an error, OfflineDumpCollect will immediately return that error
  without calling End.
- If Begin returns EFI_SUCCESS, OfflineDumpCollect will always call End(Status) and
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
OfflineDumpCollect (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL const  *pProvider
  );

#endif // _included_Library_OfflineDumpInternal_h
