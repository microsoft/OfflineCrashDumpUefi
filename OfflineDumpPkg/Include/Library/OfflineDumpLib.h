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

/**
Determines the size of the working buffer needed by the offline dump writer to
perform offline dump memory redaction. The value returned in pScratchBufferLength
can be used for the "Scratch Buffer Length" field of the "Offline Dump Capabilities"
table.

- HighestPhysicalAddress: The highest physical address in the memory map provided to
  Windows, e.g. 0x21FFFFFFFF (128GB of memory + 8GB of holes = 136GB-1).
- pScratchBufferLength: Receives the size of the working buffer needed, in bytes.

This function will return an error if HighestPhysicalAddress is greater than about
127TB because the size of the required scratch buffer would not fit in a UINT32.

This function provides accurate results when the memory map starts at an address
less than 4GB and has no 4GB holes (or larger). If the memory map has large holes,
this function will return a value that is larger than necessary.

For example, on a system with 128GB of memory and ~8GB of scattered holes in the
memory map, the highest physical address might be 0x21FFFFFFFF. This function will
compute the scratch buffer length 4464640 (4360KB) as the sum of:

  - 4KB * ceil(HighestPhysicalAddress / 2^52) = 4KB * 1 = 4KB
  - 4KB * Number of 4TB regions touched by the memory map = 4KB * 1 = 4KB
  - 128KB * Number of 4GB regions touched by the memory map = 128KB * 34 = 4352KB.
  */
EFI_STATUS
GetOfflineDumpRedactionScratchBufferLength (
  IN  UINT64  HighestPhysicalAddress,
  OUT UINT32  *pLength
  );

#endif // _included_Library_OfflineDumpLib_h
