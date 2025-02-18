/*
Microsoft Offline Dump - Functions for working with an Offline Dump.
*/

#ifndef _included_Library_OfflineDumpLib_h
#define _included_Library_OfflineDumpLib_h

#include <Uefi/UefiBaseType.h>
#include <Protocol/OfflineDumpProvider.h>
#include <Protocol/DevicePath.h>

/**
Launches OfflineDumpWrite.efi (located using device path) to write an offline dump
using information from the specified provider.

This function publishes the specified protocol, launches the application specified by
pOfflineDumpWritePath (assumed to be the path to OfflineDumpWrite.efi), and then
un-publishes the protocol.

Specifically, it does the following:

- LoadImage(FALSE, ParentImageHandle, pOfflineDumpWritePath, NULL, 0, &WriteImageHandle);
- InstallProtocolInterface(WriteImageHandle, ..., pProviderProtocol);
- StartImage(WriteImageHandle, NULL, NULL);
- UninstallProtocolInterface(ParentImageHandle, ..., pProviderProtocol);
- UnloadImage(WriteImageHandle);
**/
EFI_STATUS
OfflineDumpWriteExecutePath (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL        *pOfflineDumpWritePath
  );

/**
Launches OfflineDumpWrite.efi (previously loaded into memory) to write an offline dump
using information from the specified provider.

This function publishes the specified protocol, launches the application specified by
pOfflineDumpWriteSourceBuffer (assumed to the contents of OfflineDumpWrite.efi), and
then un-publishes the protocol.

Specifically, it does the following:

- LoadImage(FALSE, ParentImageHandle, NULL, pOfflineDumpWritePath, OfflineDumpWriteSourceSize, &WriteImageHandle);
- InstallProtocolInterface(WriteImageHandle, ..., pProviderProtocol);
- StartImage(WriteImageHandle, NULL, NULL);
- UninstallProtocolInterface(ParentImageHandle, ..., pProviderProtocol);
- UnloadImage(WriteImageHandle);
**/
EFI_STATUS
OfflineDumpWriteExecuteMemory (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN VOID                            *pOfflineDumpWriteSourceBuffer,
  IN UINTN                           OfflineDumpWriteSourceSize
  );

/**
Returns true if the specified handle represents an offline dump partition.

Specifically, all of the following must be true:

- Handle supports the BlockIo protocol.
- Handle supports the PartitionInfo protocol.
- PartitionInfo Type is GPT.
- PartitionInfo PartitionTypeGUID is gOfflineDumpPartitionTypeGuid.

Consumes:

  BaseMemoryLib
  DebugLib
  UefiBootServicesTableLib
**/
BOOLEAN
HandleIsOfflineDumpPartition (
  IN EFI_HANDLE  DeviceHandle
  );

/**
Simple behavior for locating the partition to use for offline dump:

- Looks through all partitions in the handle table.
- If exactly one Offline Dump partition is found (as determined by
  HandleIsOfflineDumpPartition), returns that partition's device handle.
- If no such partition is found or if more than one such partition is found,
  returns EFI_NOT_FOUND.

Consumes:

  BaseMemoryLib
  DebugLib
  MemoryAllocationLib
  UefiBootServicesTableLib
**/
EFI_STATUS
FindOfflineDumpPartitionHandle (
  OUT EFI_HANDLE  *pOfflineDumpDeviceHandle
  );

/**
Simple behavior for locating a raw block device that is not a partition and
does not contain any partitions. This is useful for testing on the emulator.

- Looks through all block I/O devices in the handle table.
- If exactly one non-partition device is found, returns that device's handle.
- If no such device is found or if more than one such device is found,
  returns EFI_NOT_FOUND.

Consumes:

  BaseMemoryLib
  DebugLib
  MemoryAllocationLib
  UefiBootServicesTableLib
**/
EFI_STATUS
FindOfflineDumpRawBlockDeviceHandleForTesting (
  OUT EFI_HANDLE  *pRawBlockDeviceHandle
  );

#endif // _included_Library_OfflineDumpLib_h
