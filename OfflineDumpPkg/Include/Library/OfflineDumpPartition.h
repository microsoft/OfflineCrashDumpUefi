/*
Microsoft Offline Dump - Functions for identifying Offline Dump partitions.

Consumes:
  BaseMemoryLib
  DebugLib
  MemoryAllocationLib
  UefiBootServicesTableLib
*/

#ifndef _included_Library_OfflineDumpPartition_h
#define _included_Library_OfflineDumpPartition_h

#include <Uefi/UefiBaseType.h>
#include <Protocol/PartitionInfo.h>

// Returns TRUE if the partition is an offline dump partition, i.e. if Type is
// PARTITION_TYPE_GPT and PartitionTypeGUID is gOfflineDumpPartitionTypeGuid.
BOOLEAN
IsOfflineDumpPartition (
  IN EFI_PARTITION_INFO_PROTOCOL const  *pPartitionInfo
  );

// Simple behavior for locating the partition to use for offline dump:
//
// - Looks through all partitions in the handle table.
// - If exactly one partition is found with GPT partition type GUID equal to
//   gOfflineDumpPartitionTypeGuid, returns that partition's device handle.
// - If no such partition is found or if more than one such partition is found,
//   returns EFI_NOT_FOUND.
EFI_STATUS
GetOfflineDumpPartitionHandle (
  OUT EFI_HANDLE  *pBlockDeviceHandle
  );

#endif // _included_Library_OfflineDumpPartition_h
