/*
Microsoft Offline Dump - Functions for working with an Offline Dump.
*/

#ifndef _included_Library_OfflineDumpLib_h
#define _included_Library_OfflineDumpLib_h

#include <Protocol/OfflineDumpProvider.h>

// Collects an offline dump using information from the specified provider.
//
// Consumes:
// 
//   BaseLib
//   BaseMemoryLib
//   DebugLib
//   MemoryAllocationLib
//   SynchronizationLib
//   UefiBootServicesTableLib
// 
//   BaseCryptLib
//   OpensslLib
EFI_STATUS
OfflineDumpCollect (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL const  *pProvider
  );

// Returns true if the specified handle represents an offline dump partition.
//
// Specifically, all of the following must be true:
//
// - Handle supports the BlockIo protocol.
// - Handle supports the PartitionInfo protocol.
// - PartitionInfo Type is GPT.
// - PartitionInfo PartitionTypeGUID is gOfflineDumpPartitionTypeGuid.
//
// Consumes:
//
//   BaseMemoryLib
//   DebugLib
//   UefiBootServicesTableLib
BOOLEAN
HandleIsOfflineDumpPartition (
  IN EFI_HANDLE DeviceHandle
  );

// Simple behavior for locating the partition to use for offline dump:
//
// - Looks through all partitions in the handle table.
// - If exactly one Offline Dump partition is found (as determined by
//   HandleIsOfflineDumpPartition), returns that partition's device handle.
// - If no such partition is found or if more than one such partition is found,
//   returns EFI_NOT_FOUND.
//
// Consumes:
//
//   BaseMemoryLib
//   DebugLib
//   MemoryAllocationLib
//   UefiBootServicesTableLib
EFI_STATUS
FindOfflineDumpPartitionHandle (
  OUT EFI_HANDLE  *pOfflineDumpDeviceHandle
  );

// Simple behavior for locating a raw block device that is not a partition and
// does not contain any partitions. This is useful for testing on the emulator.
//
// - Looks through all block I/O devices in the handle table.
// - If exactly one non-partition device is found, returns that device's handle.
// - If no such device is found or if more than one such device is found,
//   returns EFI_NOT_FOUND.
//
// Consumes:
//
//   BaseMemoryLib
//   DebugLib
//   MemoryAllocationLib
//   UefiBootServicesTableLib
EFI_STATUS
FindOfflineDumpRawBlockDeviceHandleForTesting (
  OUT EFI_HANDLE  *pRawBlockDeviceHandle
  );

#endif // _included_Library_OfflineDumpLib_h
