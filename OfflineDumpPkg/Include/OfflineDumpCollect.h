/*
Microsoft Offline Dump - Writes a dump to a block device.

Consumes:

  BaseLib
  BaseMemoryLib
  DebugLib
  MemoryAllocationLib
  SynchronizationLib
  UefiBootServicesTableLib

  BaseCryptLib
  OpensslLib
*/

#ifndef _included_OfflineDumpCollect_h
#define _included_OfflineDumpCollect_h

#include <Protocol/OfflineDumpConfiguration.h>

EFI_STATUS
OfflineDumpCollect (
  IN OFFLINE_DUMP_CONFIGURATION_PROTOCOL const  *pConfiguration
  );

#endif // _included_OfflineDumpCollect_h
