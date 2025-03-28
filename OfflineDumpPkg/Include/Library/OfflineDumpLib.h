// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

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
Determines the length of the working buffer needed by the offline dump writer to
perform offline dump memory redaction. The value returned in pLength
can be used for the "Scratch Buffer Length" field of the "Offline Dump Capabilities"
table.

- HighestPhysicalAddress: The highest physical address in the memory map provided to
  Windows, e.g. 0x21FFFFFFFF (128GB of memory + 8GB of holes = 136GB-1).
  HighestPhysicalAddress + 1 must be a multiple of 4096 (i.e.
  HighestPhysicalAddress must end with 0xFFF).

- pLength: Receives the length of the working buffer needed, in bytes.

Returns:

- EFI_SUCCESS if the length was computed successfully.
- EFI_INVALID_PARAMETER if HighestPhysicalAddress is greater than 0x7FFDFFFFFFFF
  or if HighestPhysicalAddress + 1 is not a multiple of 4096.

Remarks:

This function should be used when the memory map provided to Windows has no
large gaps (holes 4GB or larger). If the memory map has large gaps, the result
returned by this function may be larger than necessary. In that case, the caller
should use the OfflineDumpRedactionScratchBufferLength_* functions to compute
the required length instead of using this function.

Example:

On a system with 128GB of memory and ~8GB of scattered holes in the memory map, the
highest physical address might be 136GB-1 = 0x21FFFFFFFF. For 0x21FFFFFFFF, this
function will compute the scratch buffer length 4464640 (4360KB) as the sum of:

  - 4KB * ceil(HighestPhysicalAddress / 2^52) = 4KB * 1 = 4KB
  - 4KB * Number of 4TB regions touched by the memory map = 4KB * 1 = 4KB
  - 128KB * Number of 4GB regions touched by the memory map = 128KB * 34 = 4352KB.
*/
EFI_STATUS
GetOfflineDumpRedactionScratchBufferLength (
  IN  UINT64  HighestPhysicalAddress,
  OUT UINT32  *pLength
  );

/**
Used with OfflineDumpRedactionScratchBufferLength_* functions to compute the length of the
working buffer needed by the offline dump writer to perform offline dump memory redaction.
The value returned by OfflineDumpRedactionScratchBufferLength_Get can be used for the
"Scratch Buffer Length" field of the "Offline Dump Capabilities" table.

The OfflineDumpRedactionScratchBufferLength_* functions should be used when the
memory map has large gaps (holes of 4GB or more). In simple cases when the
memory map does not have any large gaps, the length can be computed using
GetOfflineDumpRedactionScratchBufferLength.

Usage:

- Declare a context (OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT) variable.
- Call OfflineDumpRedactionScratchBufferLength_Init to initialize the context.
- Call OfflineDumpRedactionScratchBufferLength_AddMemRange once for each range of memory in
  the memory map, in order from lowest address to highest address.
- Call OfflineDumpRedactionScratchBufferLength_Get to get the length of the scratch buffer.

Note that the ranges provided to OfflineDumpRedactionScratchBufferLength_AddMemRange must be
non-overlapping and must be provided in order of the range's base address (lowest to highest).
*/
typedef struct {
  INT64      LastPageNum;
  UINT32     BitmapCount;
  UINT16     Table1Count;
  UINT8      Initialized;
  BOOLEAN    AnyErrors;
} OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT;

/**
Initializes the OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT for computing the
length of the scratch buffer needed for redaction.

For details, see OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT.
*/
void
OfflineDumpRedactionScratchBufferLength_Init (
  OUT OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  *pContext
  );

/**
Updates the OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT with the specified
range of memory. This must be called with non-overlapping ranges of memory, ordered by address
(lowest to highest). Addresses and lengths must be multiples of 4KB.

For details, see OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT.
*/
EFI_STATUS
OfflineDumpRedactionScratchBufferLength_AddMemRange (
  IN OUT OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  *pContext,
  IN UINT64                                                    BaseAddress,
  IN UINT64                                                    Length
  );

/**
Computes the length of the scratch buffer needed for redaction, in bytes. This function
must be called after all ranges of memory have been added using
OfflineDumpRedactionScratchBufferLength_AddMemRange.

For details, see OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT.

This function will return an error if the context is not valid (e.g. not initialized) or
if any errors have been returned by any call to AddMemRange.

This may return a length larger than 4GB. The current "Offline Dump Capabilities"
table does not support scratch buffers larger than 4GB, so the caller should
check the returned length and not use it with the current table if it is larger
than 4GB.
*/
EFI_STATUS
OfflineDumpRedactionScratchBufferLength_Get (
  IN OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT const  *pContext,
  OUT UINT64                                                     *pLength
  );

#endif // _included_Library_OfflineDumpLib_h
