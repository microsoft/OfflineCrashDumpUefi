/*
Microsoft Offline Dump - Function to collect an Offline Dump.
*/

#ifndef _included_Library_OfflineDumpCollectLib_h
#define _included_Library_OfflineDumpCollectLib_h

#include <Protocol/OfflineDumpProvider.h>

/**
Collects an offline dump using information from the specified provider.

Static-link with this function to collect an offline dump.

Alternatively, invoke OfflineDumpCollect.efi as an application using one of
the OfflineDumpCollectExecutePath or OfflineDumpCollectExecuteMemory functions.

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

#endif // _included_Library_OfflineDumpCollectLib_h
