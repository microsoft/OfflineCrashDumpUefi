// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Functions for writing dump data to a block device.

PRELIMINARY DESIGN:

The DUMP_WRITER object implements writing section data to a block device, handling
block I/O and full-dump encryption. It does not handle memory/CPU redaction, memory
region encryption, or other aspects of the dump process.

This is not the intended final interface. Current interface is intended to simplify
development and testing. Intended final interface will handle higher-level operations
like memory redaction and encryption. The final interface will likely be a single
WriteDump function that accepts a pDumpConfigurationProtocol pointer.

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

#ifndef _included_OfflineDumpWriter_h
#define _included_OfflineDumpWriter_h

#include <Uefi/UefiBaseType.h>
#include <Guid/OfflineDumpHeaders.h>

// Forward decaration of the opaque OFFLINE_DUMP_WRITER object.
typedef struct OFFLINE_DUMP_WRITER OFFLINE_DUMP_WRITER;

// Options for adjusting the behavior of a DumpWriter.
typedef struct OFFLINE_DUMP_WRITER_OPTIONS {
  // If false, use BLOCK_IO_PROTOCOL only if BLOCK_IO2_PROTOCOL is not supported.
  // If true, always use BLOCK_IO_PROTOCOL.
  //
  // Set this to true if the underlying device supports BLOCK_IO2_PROTOCOL but doesn't
  // support efficient async I/O. This will cause the writer to use BLOCK_IO_PROTOCOL and
  // synchronous I/O instead of BLOCK_IO2_PROTOCOL with async I/O. On devices that support
  // BLOCK_IO2_PROTOCOL but don't fully support async I/O, this can improve performance.
  // For example, the current EDK2 implementation of the AHCI driver supports BLOCK_IO2
  // but always completes the I/O synchonously, so it would be more efficient to use
  // BLOCK_IO for AHCI devices.
  //
  // May also be useful for testing or debugging.
  BOOLEAN    DisableBlockIo2;

  // If false, use OfflineMemoryDumpEncryptionAlgorithm variable to determine encryption.
  // If true, ignore OfflineMemoryDumpEncryptionAlgorithm and always write an unencrypted
  // dump.
  //
  // This is useful for testing or debugging. This flag must not be set for production
  // builds.
  BOOLEAN    ForceUnencrypted;

  // Number of buffers to use for async I/O. Significant only if the device supports
  // async I/O (EFI_BLOCK_IO2_PROTOCOL).
  //
  // - If this is 0, a default value will be selected.
  // - If this is 1, it will be set to 2.
  // - If EFI_BLOCK_IO2_PROTOCOL is not supported by the device or if the DisableBlockIo2
  //   flag is set, this value will be ignored. In this case, the writer always use one
  //   large buffer for writing data and one small buffer for writing headers.
  UINT8    BufferCount;

  // Maximum total bytes to allocate for the dump writer's I/O buffers (soft limit).
  //
  // This is used to determine
  //
  //   BufferSize = RoundDownToBlockSize(BufferMemoryLimit / BufferCount).
  //
  // - If this is 0, a default value will be selected.
  // - If this is less than BlockSize * BufferCount, it will be set to
  //   BlockSize * BufferCount.
  //
  // Note this does not cap total memory usage of the writer. The dump writer also
  // allocates other memory, e.g. it allocates SectionCountExpected * 64 bytes to track
  // section headers.
  UINT32    BufferMemoryLimit;
} OFFLINE_DUMP_WRITER_OPTIONS;

// Finalizes the dump and deletes the dump writer.
// May block on write operations (writing headers, flushing blocks).
//
// This method does the following:
//
// 1. Flushes any pending data.
// 2. Waits for all pending I/O operations to complete.
// 3. Updates dump header Flags field:
//    - If OfflineDumpWriterLastError() != 0, does not modify the header flags (dump
//      invalid).
//    - Else if OfflineDumpWriterHasInsufficientStorage(), sets the INSUFFICIENT_STORAGE
//      flag.
//    - Else if DumpValid, sets the DUMP_VALID flag.
//    - Else does not modify the header flags (dump invalid).
// 4. Status = FlushHeaders() && pBlockIo->FlushBlocks().
// 5. Deletes pDumpWriter.
// 6. Returns Status.
EFI_STATUS
OfflineDumpWriterClose (
  IN OUT OFFLINE_DUMP_WRITER  *pDumpWriter,
  IN BOOLEAN                  DumpValid
  );

// Creates a new OFFLINE_DUMP_WRITER object for writing a dump to the specified device.
// May block on a write operation (writing headers).
//
// DumpDeviceHandle: must support either EFI_BLOCK_IO_PROTOCOL or EFI_BLOCK_IO2_PROTOCOL.
//      EFI_BLOCK_IO2_PROTOCOL is preferred (supports async I/O, improves performance).
//      This device will usually be a partition handle.
//
// DumpHeaderFlags: flags for the dump header. This must not include the DUMP_VALID or
//      INSUFFICIENT_STORAGE flags (they are managed automatically by the writer).
//
// SectionCountExpected: the maximum number of sections that can be written to the dump.
//      This is used to pre-allocate space for the section headers. It is ok if the
//      actual number of sections written is less than this.
//
// This method does the following:
//
// 1. Reads dump settings from UEFI variables: OfflineMemoryDumpOsData,
//    OfflineMemoryDumpEncryptionAlgorithm, OfflineMemoryDumpEncryptionPublicKey.
// 2. Validate settings (i.e. fail if encryption algorithm is not supported or if
//    certificate cannot be parsed).
// 3. Verifies that the device supports EFI_BLOCK_IO2_PROTOCOL or EFI_BLOCK_IO_PROTOCOL.
// 4. Allocates buffers.
// 5. Writes initial dump headers to dump device (DUMP_VALID flag not set).
//
// If an error is encountered, sets *ppDumpWriter == NULL and returns an error status.
// Otherwise, sets *ppDumpWriter to the new OFFLINE_DUMP_WRITER object and returns
// success.
EFI_STATUS
OfflineDumpWriterOpen (
  IN EFI_HANDLE                         DumpDeviceHandle,
  IN RAW_DUMP_HEADER_FLAGS              DumpHeaderFlags,
  IN UINT32                             SectionCountExpected,
  IN OFFLINE_DUMP_WRITER_OPTIONS const  *pOptions OPTIONAL,
  OUT OFFLINE_DUMP_WRITER               **ppDumpWriter
  );

// If any block write operations have failed, returns the error status of the most
// recent failure. Otherwise, returns EFI_SUCCESS.
//
// Note that OfflineDumpWriterClose() will automatically mark the dump as "invalid" if
// any block write operations fail.
EFI_STATUS
OfflineDumpWriterLastWriteError (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns the device position to which the next OfflineDumpWriterWriteSectionData() will
// write.
//
// This is not the same as the raw dump offset -- this value includes the size of the
// encryption header (if any). This may be larger than OfflineDumpWriterMediaSize() if
// the device is too small for the written data.
UINT64
OfflineDumpWriterMediaPosition (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns the size of the device.
UINT64
OfflineDumpWriterMediaSize (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns the size of the I/O buffer used by the dump writer.
UINT32
OfflineDumpWriterBufferSize (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns the number of I/O buffers used by the dump writer.
UINT8
OfflineDumpWriterBufferCount (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns the ENC_DUMP_ALGORITHM used by the dump writer.
UINT32
OfflineDumpWriterEncryptionAlgorithm (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns true if the dump writer is using EFI_BLOCK_IO2_PROTOCOL for async I/O.
BOOLEAN
OfflineDumpWriterUsingBlockIo2 (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Returns true if the dump writer has run out of storage space, i.e. returns
// OfflineDumpWriterMediaSize() < OfflineDumpWriterMediaPosition().
//
// Note that OfflineDumpWriterClose() will automatically mark the dump as "insufficient
// storage" if this is true.
//
// Note that caller should still write the rest of the sections to the dump so that the
// TotalDumpSizeRequired field can be calculated correctly.
BOOLEAN
OfflineDumpWriterHasInsufficientStorage (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Gets the dump header.
// Caller should not modify the header. The header fields are managed automatically by
// the writer.
RAW_DUMP_HEADER const *
OfflineDumpWriterGetDumpHeader (
  IN OFFLINE_DUMP_WRITER const  *pDumpWriter
  );

// Flushes the current dump headers to the dump device.
// May block on a write operation.
//
// Headers will be written automatically as part of OfflineDumpWriterClose(), but you may
// call this method at other times to save progress in case dump is interrupted.
//
// This is a best-effort method because the headers will be written again as part of
// OfflineDumpWriterClose(). An error in OfflineDumpWriterFlushHeaders() will not affect
// OfflineDumpWriterLastWriteError() and will not invalidate the dump.
//
// Returns a status code indicating whether the headers were flushed.
EFI_STATUS
OfflineDumpWriterFlushHeaders (
  IN OUT OFFLINE_DUMP_WRITER  *pDumpWriter
  );

// Callback to use for reading the section data, e.g. to access fenced memory regions.
//
// pDataStart: The value of the pDataStart parameter that was passed to
//     OfflineDumpWriterWriteSection.
//
// Offset: offset into the section. This will always be less than the DataSize parameter
//     that was passed to OfflineDumpWriterWriteSection. This will always be a multiple
//     of 16.
//
// Size: number of bytes to read. Offset + Size will always be less than or equal to the
//     DataSize parameter that was passed to OfflineDumpWriterWriteSection. Size will
//     always be a multiple of 16 unless DataSize was not, in which case the final call
//     to this callback will have a Size that is not a multiple of 16 (to read the last
//     bytes).
//
// pDestinationPos: destination buffer for the data. Buffer has room for Size bytes.
//     Important: Copy to pDestinationPos[0..Size]. Do not add Offset to this pointer.
//
// Returns: TRUE on success, FALSE if copy failed. FALSE will cause the section to be
//          trucated to the last successfully-copied offset and the section to be
//          marked as invalid (the dump will not be marked as invalid).
//
// Section data will be copied by code that looks approximately like this:
//
// UINT8 DestinationBuffer[SomeMultipleOf16];
// for (UINT64 Offset = 0; Offset < DataSize; Offset += sizeof(DestinationBuffer)) {
//   UINTN Size = (UINTN)MIN(DataSize - Offset, sizeof(DestinationBuffer));
//   if (DataCallback == NULL) {
//      CopyMem(DestinationBuffer, pDataStart + Offset, Size);
//   } else if (!DataCallback(pDataStart, Offset, Size, DestinationBuffer)) {
//      Section->Flags &= ~RAW_DUMP_SECTION_HEADER_DUMP_VALID; // Mark section as invalid.
//      Section->Size = Offset; // Truncate section size to the last successfully-copied offset.
//      break; // Stop copying data for this section (continue to other sections).
//   }
//   AppendToDump(DestinationBuffer, Size);
// }
//
typedef
  BOOLEAN
(EFIAPI *DUMP_WRITER_COPY_CALLBACK)(
                                    IN VOID const *pDataStart,
                                    IN UINTN      Offset,
                                    IN UINTN      Size,
                                    OUT UINT8     *pDestinationPos
                                    );

// Fills in the header and writes the data for the next section.
// May block on a write operation (writing section data).
//
// Flags: flags for the section header.
//
//   - This MUST NOT include the INSUFFICIENT_STORAGE flag because that flag is managed
//     automatically by the writer.
//   - This should usually include the DUMP_VALID flag to mark the section as valid. (The
//     dump writer may remove the DUMP_VALID flag if an error occurs while copying the
//     section data.)
//
// MajorVersion, MinorVersion: version of the section data structure, usually { 1, 0 }.
//
// Type: type of the section.
//
// pInformation: information for the section header. The active field is selected by
//      Type.
//
// pName: name of the section. Must be a null-terminated string. If the name is longer
//      than 20 characters, it will be truncated.
//
// DataCallback: Callback to use for reading the section data. If NULL, the section data
//      will be copied directly. If non-NULL, the callback will be invoked as:
//
//      Ok = DataCallback(pDataStart, Offset, Size, pDestinationPos);
//
// pDataStart: start of the section data. If DataCallback is NULL, this is a pointer to
//      the section data. If DataCallback is non-NULL, this is an opaque value that will
//      be passed to the callback (when using a callback, the pDataStart parameter is
//      just a context value and does not need to be a real pointer).
//
// DataSize: size of the section data in bytes.
//
// Returns:
//
//   - error for invalid parameter or if SectionCountExpected sections have already
//     been written.
//   - success otherwise. Returns success even if there is insufficient storage to write
//     the data or if an error occurs while copying or writing the data. Check
//     OfflineDumpWriterLastWriteError() and OfflineDumpWriterHasInsufficientStorage() to
//     determine whether one of those conditions occurred.
//
// This method does the following:
//
// 1. Fills in the section header as described by the parameters.
// 2. Writes the section data to the dump device.
// 3. If there was not enough space to write the section data, sets the
//    INSUFFICIENT_STORAGE flag in the dump header and clears the DUMP_VALID flag.
// 4. If an error was returned by the callback while copying section data, clears the
//    DUMP_VALID flags in the section header and dump header.
// 5. Updates the dump header TotalDumpSizeRequired, DumpSize, SectionsCount fields.
//
// This does not flush the updated headers to disk. Headers will be flushed to disk as
// part of OfflineDumpWriterClose(), or you may call OfflineDumpWriterFlushHeaders() to
// save progress in case the dump is interrupted.
EFI_STATUS
OfflineDumpWriterWriteSection (
  IN OUT OFFLINE_DUMP_WRITER             *pDumpWriter,
  IN RAW_DUMP_SECTION_HEADER_FLAGS       SectionHeaderFlags,
  IN UINT16                              MajorVersion,
  IN UINT16                              MinorVersion,
  IN RAW_DUMP_SECTION_TYPE               Type,
  IN RAW_DUMP_SECTION_INFORMATION const  *pInformation,
  IN CHAR8 const                         *pName,
  IN DUMP_WRITER_COPY_CALLBACK           DataCallback OPTIONAL,
  IN void const                          *pDataStart,
  IN UINTN                               DataSize
  );

#endif // _included_OfflineDumpWriter_h
