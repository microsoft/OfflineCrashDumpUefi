/*
Microsoft Offline Dump - Functions for identifying Offline Dump partitions.

Consumes:
  BaseMemoryLib      (CompareGuid)
*/

#ifndef _included_Library_OfflineDumpPartition_h
#define _included_Library_OfflineDumpPartition_h

#include <Uefi/UefiBaseType.h>
#include <Protocol/PartitionInfo.h>

// Returns TRUE if the partition is an SVRawDump partition, i.e. if Type is
// PARTITION_TYPE_GPT and PartitionTypeGUID is gOfflineDumpPartitionTypeGuid.
BOOLEAN
PartitionIsSVRawDump (
  IN EFI_PARTITION_INFO_PROTOCOL const  *pPartitionInfo
  );

#endif // _included_Library_OfflineDumpPartition_h
