/** @file
  Microsoft Offline Dump provider protocol - implemented by platform ISV.

  The ISV implements this protocol to provide dump information to the
  Offline Crash Dump collector and to configure collector behavior.

  - OFFLINE_DUMP_PROVIDER_PROTOCOL (struct)
  - OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION (enum)
  - OFFLINE_DUMP_PROVIDER_DUMP_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_SECTION (struct)
  - OFFLINE_DUMP_COLLECTOR_INFO (struct)
  - OFFLINE_DUMP_OPTIONS (struct)

  - OFFLINE_DUMP_PROVIDER_BEGIN (function pointer)
  - OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS (function pointer)
  - OFFLINE_DUMP_PROVIDER_END (function pointer)
  - OFFLINE_DUMP_DATA_COPY (function pointer)

  TODO: Better names for structures, OfflineDumpCollect.efi?
**/

#ifndef _included_Protocol_OfflineDumpProvider_h
#define _included_Protocol_OfflineDumpProvider_h

#include <Guid/OfflineDumpConfig.h>
#include <Guid/OfflineDumpEncryption.h>
#include <Guid/OfflineDumpHeaders.h>

// {56B79CF2-9D1F-42FC-B45A-16BBBA5C623A}
#define OFFLINE_DUMP_PROVIDER_PROTOCOL_GUID \
  { 0x56b79cf2, 0x9d1f, 0x42fc, { 0xb4, 0x5a, 0x16, 0xbb, 0xba, 0x5c, 0x62, 0x3a } }

/**
  Protocol implemented by platform ISV to provide dump information to the Offline
  Crash Dump Collector and to configure collector behavior.

  - ISV implements this protocol and installs the protocol instance into the EFI handle table.
  - ISV launches OfflineDumpCollect.efi.
  - OfflineDumpCollect.efi locates the protocol in the EFI handle table.
  - OfflineDumpCollect.efi calls the protocol's Begin function to get dump parameters.
  - OfflineDumpCollect.efi writes the dump data, periodically calling the protocol's ReportProgress function.
  - OfflineDumpCollect.efi calls the protocol's End function.
  - OfflineDumpCollect.efi exits.
  - ISV updates dump status variables and reboots.

**/
typedef struct _OFFLINE_DUMP_PROVIDER_PROTOCOL OFFLINE_DUMP_PROVIDER_PROTOCOL;

/**
  Revision of the OFFLINE_DUMP_PROVIDER_PROTOCOL interface that a component supports.

  The protocol implementation (provider) specifies its revision in the Revision field
  of the OFFLINE_DUMP_PROVIDER_PROTOCOL protocol structure. The collector uses this value
  to determine which fields of the protocol structure can be accessed. It will never access
  fields that were added in a later revision and will use a default value instead (typically
  NULL or 0).

  The collector implementation specifies its revision value when calling the Begin
  function. The provider uses this value to determine which features the
  collector supports. For example, if a new section type is added in a future version of the
  specification, the provider can use the revision value to determine whether
  the new section type will be recognized.

**/
typedef enum {
  OfflineDumpProviderProtocolRevision_1_0    = 0x00010000,
  OfflineDumpProviderProtocolRevisionCurrent = OfflineDumpProviderProtocolRevision_1_0,
} OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION) == 4,
               "OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION should be 4 bytes"
               );

/**
  Callback used for reading the section data, e.g. to access fenced memory regions.
  Used in the OFFLINE_DUMP_PROVIDER_SECTION structure's DataCopyCallback field.

  @param[in]  pDataStart      The value of the opaque pDataStart parameter that was set in
                              OFFLINE_DUMP_PROVIDER_SECTION.
  @param[in]  Offset          Offset into the section. This will always be less than the DataSize
                              parameter that was set in OFFLINE_DUMP_PROVIDER_SECTION.
                              This will always be a multiple of 16.
  @param[in]  Size            Number of bytes to read. Offset + Size will always be less than or
                              equal to the DataSize parameter that was set in
                              OFFLINE_DUMP_PROVIDER_SECTION. Size will always be a
                              multiple of 16 unless DataSize was not, in which case the final call
                              to this callback will have a Size that is not a multiple of 16 (to
                              read the last bytes).
  @param[out] pDestinationPos Destination buffer for the data. Buffer has room for Size bytes.
                              Important: Copy to pDestinationPos[0..Size]. Do not add Offset to this
                              pointer.

  @retval TRUE  The data was successfully copied to pDestinationPos.
  @retval FALSE The data could not be copied to pDestinationPos. The section will be truncated
                to the last successfully-copied offset and the section will be marked as invalid.
                (Does not make the dump invalid. Does not prevent writing subsequent sections.)

  Section data will be copied by code that looks approximately like this:

  UINT8 DestinationBuffer[MultipleOf16];
  for (UINT64 Offset = 0; Offset < DataSize; Offset += sizeof(DestinationBuffer)) {
    UINTN Size = (UINTN)MIN(DataSize - Offset, sizeof(DestinationBuffer));
    if (DataCopyCallback == NULL) {
      // Fast path - treat pDataStart as a pointer to normal readable memory.
      // May implement some optimizations, e.g. may inline data processing.
      CopyMem(DestinationBuffer, (UINT8 const*)pDataStart + Offset, Size);
    } else {
      // Flexible path - treat pDataStart as an opaque context value for the callback.
      if (!DataCopyCallback(pProtocol, pDataStart, Offset, Size, DestinationBuffer)) {
        Section->Flags &= ~RAW_DUMP_SECTION_HEADER_DUMP_VALID; // Mark section as invalid.
        Section->Size = Offset; // Truncate section size to the last successfully-copied offset.
        break; // Stop copying data for this section (continue to other sections).
      }
    }
    AppendToDump(DestinationBuffer, Size);
  }

**/
typedef
  BOOLEAN
(EFIAPI *OFFLINE_DUMP_DATA_COPY)(
                                 IN VOID const *pDataStart,
                                 IN UINTN      Offset,
                                 IN UINTN      Size,
                                 OUT UINT8     *pDestinationPos
                                 );

/**
  Information about the collector passed to the provider's Begin function.

  The collector provides this information to the protocol implementation (provider) when calling the
  Begin function. The provider uses this information to configure its behavior.

  If the collector and the provider are compiled against different revisions of the
  protocol, they may disagree on the size of this structure. The provider's Begin
  function should only read the first CollectorInfoSize bytes of the pCollectorInfo buffer. One way
  to handle this is to use a copy of the structure. For example, the Begin function might have
  code like this:

    OFFLINE_DUMP_COLLECTOR_INFO CollectorInfoCopy = { 0 };
    CopyMem(&CollectorInfoCopy, pCollectorInfo, MIN(sizeof(CollectorInfoCopy), CollectorInfoSize));
    // ... Use CollectorInfoCopy rather than reading from pCollectorInfo ...
**/
typedef struct {
  //
  // The revision of the collector that is calling this function.
  //
  // The protocol implementation (provider) uses this value to determine which features the
  // collector supports. For example, if a new section type is added in a future version of the
  // specification, the provider can use the revision value to determine whether
  // the new section type will be recognized.
  //
  OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION    CollectorRevision;

  //
  // The capability flags that are requested by the high-level operating system.
  //
  OFFLINE_DUMP_USE_CAPABILITY_FLAGS          UseCapabilityFlags;
} OFFLINE_DUMP_COLLECTOR_INFO;

/**
  Information provided by the protocol implementation (provider) to the collector to control collector
  behavior. This information is provided in the Options field of
  OFFLINE_DUMP_PROVIDER_DUMP_INFO.
**/
typedef struct {
  //
  // Maximum total bytes to allocate for the dump collector's I/O buffers (soft limit). If
  // this is 0, the collector will select a reasonable default (currently 3MB).
  //
  // - If BufferMemoryLimit == 0 then ActualBufferMemoryLimit will be set to a default
  //   value.
  // - Else if BufferMemoryLimit < BlockSize * ActualBufferCount then
  //   ActualBufferMemoryLimit will be set to BlockSize * ActualBufferCount.
  // - Else ActualBufferMemoryLimit will be set to BufferMemoryLimit.
  //
  // This value is used to determine
  // ActualBufferSize = RoundDownToBlockSize(ActualBufferMemoryLimit / ActualBufferCount).
  //
  // Note that this does not cap total memory usage of the collector. The dump collector also
  // allocates several other buffers, e.g. it allocates SectionCount * 64 bytes to track
  // section headers.
  //
  UINT32    BufferMemoryLimit;

  //
  // Number of data buffers to use for async I/O. Significant only if the device supports
  // async I/O (EFI_BLOCK_IO2_PROTOCOL). If this is 0, the collector will select a
  // reasonable default (currently 3).
  //
  // Current implementation:
  //
  // - If the device only supports EFI_BLOCK_IO_PROTOCOL or if DisableBlockIo2 is TRUE
  //   then ActualBufferCount will be set to 1.
  // - Else if BufferCount == 0 then ActualBufferCount will be set to a default value.
  // - Else if BufferCount < 2 then ActualBufferCount will be set to 2.
  // - Else ActualBufferCount will be set to BufferCount.
  //
  UINT8    BufferCount;

  //
  // If TRUE, the collector will use EFI_BLOCK_IO_PROTOCOL (synchronous I/O) even if the
  // device supports EFI_BLOCK_IO2_PROTOCOL. Set this to improve performance if a
  // device implements the BLOCK_IO2 protocol but does not actually implement async
  // operations, e.g. the EDK2 ATA driver.
  //
  // Implementation detail: in addition to forcing the use of EFI_BLOCK_IO_PROTOCOL, this
  // flag also affects how the collector manages buffers. Since the device does not support
  // async I/O, the collector will allocate one large buffer instead of several smaller buffers.
  //
  BOOLEAN    DisableBlockIo2  : 1;

  //
  // For testing/debugging purposes.
  // If TRUE, the collector will not set the DUMP_VALID flag when finalizing the dump.
  //
  BOOLEAN    ForceDumpInvalid : 1;

  //
  // For testing/debugging purposes - production builds MUST NOT set this flag.
  // If TRUE, the collector should not encrypt the dump.
  //
  BOOLEAN    ForceUnencrypted : 1;

  //
  // Reserved - must be set to 0.
  //
  BOOLEAN    Reserved1        : 5;

  //
  // Reserved - must be set to 0.
  //
  UINT16     Reserved2;
} OFFLINE_DUMP_OPTIONS;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_OPTIONS) == 8,
               "OFFLINE_DUMP_OPTIONS should be 8 bytes"
               );

/**
  Information provided by the protocol implementation (provider) to the collector about a section to be included
  in the dump. This information is provided in the pSections field of OFFLINE_DUMP_PROVIDER_DUMP_INFO.

  Note that in some cases, a single OFFLINE_DUMP_PROVIDER_SECTION element may result in
  multiple sections being written to the dump, or it may be ignored entirely. For example:

  - A single DDR_RANGE section may result in multiple DDR sections being written to the dump, e.g. if
    parts of the section contain secure-kernel data and need to be redacted.
  - If the collector does not support a section type or does not support a requested action, it will ignore
    the section and will not write it to the dump.
**/
typedef struct {
  //
  // Section type, e.g. DDR_RANGE or SV_SPECIFIC.
  //
  RAW_DUMP_SECTION_TYPE            Type;

  //
  // Normally NONE. Should not include DUMP_VALID or INSUFFICIENT_STORAGE.
  //
  RAW_DUMP_SECTION_HEADER_FLAGS    Flags;

  //
  // Section name. Ends at first '\0', or at 20 chars. Not guaranteed to be unique.
  // If this is set to "" then the collector will provide a default name for the section.
  // DDR_RANGE section names should start with "DDR".
  //
  // TODO: guidance for section names.
  //
  CHAR8 const                     *pName;

  //
  // Additional information about the section. The format of this information depends on the
  // section type. For example, if Type=DDR_RANGE, the Information.DdrRange field of the union
  // must be filled-in.
  //
  RAW_DUMP_SECTION_INFORMATION    Information;

  //
  // Size of the section data.
  //
  UINT64                          DataSize;

  //
  // If DataCopyCallback == NULL, this is a pointer to the section data (must be normal readable memory).
  //
  // If DataCopyCallback != NULL, this is an opaque context value that will be passed to DataCopyCallback.
  //
  VOID const                      *pDataStart;

  //
  // If DataCopyCallback == NULL, the collector will treat pDataStart as a pointer to normal readable memory
  // and will access it directly. (Preferred - this allows the collector to optimize the data copy.)
  //
  // If DataCopyCallback != NULL, the collector will treat pDataStart as an opaque context value and will call
  // DataCopyCallback as needed to read the section data. This might be used for data that is
  // generated/filtered on-the-fly or for data that is copied by a co-processor from a fenced region.
  //
  OFFLINE_DUMP_DATA_COPY    DataCopyCallback;

  //
  // Normally FALSE. If TRUE, indicates that the collector should not set the DUMP_VALID flag
  // for the section.
  //
  BOOLEAN                   ForceInvalid;

  //
  // Must be set to 0. (Potential future use: SectionAction)
  //
  UINT8                     Reserved1;

  //
  // Must be set to 0. (Potential future use: SectionActionData)
  //
  UINT16                    Reserved2;

  //
  // Must be set to 0.
  //
  UINT32                    Reserved3;

  //
  // Must be set to NULL. (Potential future use: extended section configuration.)
  //
  VOID const                *Reserved4;
} OFFLINE_DUMP_PROVIDER_SECTION;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_SECTION) == 72,
               "OFFLINE_DUMP_PROVIDER_SECTION should be 72 bytes"
               );

/**
  Dump configuration information returned to the collector by the provider's
  Begin function.

  If the collector and the provider are compiled against different revisions of the
  protocol, they may disagree on the size of this structure. The provider's Begin
  function should only write the first DumpInfoSize bytes of the pDumpInfo buffer. One way
  to handle this is to use a copy of the structure. For example, the Begin function might have
  code like this:

    OFFLINE_DUMP_PROVIDER_DUMP_INFO DumpInfoCopy = { 0 };
    // ... Initialize DumpInfoCopy rather than writing to pDumpInfo ...
    CopyMem(pDumpInfo, &DumpInfoCopy, MIN(DumpInfoSize, sizeof(DumpInfoCopy)));
*/
typedef struct {
  //
  // Configuration options for the collector. Usually the default (0) values are ok.
  //
  OFFLINE_DUMP_OPTIONS    Options;

  //
  // The block device to which the dump should be written, or NULL for default device.
  //
  // If set to non-NULL, the collector will use the specified device. The device must implement
  // EFI_BLOCK_IO2_PROTOCOL (preferred) or EFI_BLOCK_IO_PROTOCOL. Normally the device is the
  // handle of a partition, not the handle of a physical device. The dump will be written
  // directly to this device, starting at LBA 0 (no filesystem is involved).
  //
  // If set to NULL, the collector will attempt to locate an appropriate device, guided by the
  // value of the OfflineMemoryDumpUseCapability variable. If the collector is unable to find
  // an appropriate device, the collector will fail to write a dump and will end the dump with
  // status EFI_NOT_FOUND.
  //
  EFI_HANDLE    BlockDevice;

  //
  // Pointer to an OFFLINE_DUMP_PROVIDER_SECTION[SectionCount] array with the
  // information for DDR_RANGE and SV_SPECIFIC sections to be included in the dump.
  //
  // This should not include CPU_CONTEXT, DUMP_REASON, or SYSTEM_INFORMATION sections.
  // The collector will automatically add these sections based on the information provided
  // below.
  //
  OFFLINE_DUMP_PROVIDER_SECTION const    *pSections;

  //
  // Number of elements in the pSections array.
  //
  UINT32                                 SectionCount;

  //
  // Indicates the CPU architecture of the system. This is used in the generated
  // CPU_CONTEXT and SYSTEM_INFORMATION sections.
  //
  RAW_DUMP_ARCHITECTURE                  Architecture;

  //
  // Pointer to an array of CPU context structures, one for each core on the system. This
  // is used in the generated CPU_CONTEXT section.
  //
  // - If Architecture == RAW_DUMP_ARCHITECTURE_ARM64, this should point at a
  //   CONTEXT_ARM64[CpuContextCount] array.
  // - If Architecture == RAW_DUMP_ARCHITECTURE_X64, this should point at a
  //   CONTEXT_AMD64[CpuContextCount] array.
  //
  // The CONTEXT_ARM64 and CONTEXT_AMD64 structures are defined in <Guid/OfflineDumpCpuContext.h>.
  //
  VOID const    *pCpuContexts;

  //
  // Number of elements in the pCpuContexts array (number of cores on the system).
  //
  UINT32        CpuContextCount;

  //
  // The size of each element in the pCpuContexts array.
  //
  // - If Architecture == RAW_DUMP_ARCHITECTURE_ARM64, this should be sizeof(CONTEXT_ARM64).
  // - If Architecture == RAW_DUMP_ARCHITECTURE_X64, this should be sizeof(CONTEXT_AMD64).
  //
  // The CONTEXT_ARM64 and CONTEXT_AMD64 structures are defined in <Guid/OfflineDumpCpuContext.h>.
  //
  UINT32                   CpuContextSize;

  //
  // 4-character vendor ACPI ID. This is used in the generated SYSTEM_INFORMATION section.
  //
  CHAR8 const              *pVendor;

  //
  // 8-character silicon vendor platform ID. This is used in the generated SYSTEM_INFORMATION
  // section.
  //
  CHAR8 const              *pPlatform;

  //
  // Bucketization parameters for the dump. These are used in the generated DUMP_REASON
  // section.
  //
  UINT32                   DumpReasonParameter1;
  UINT32                   DumpReasonParameter2;
  UINT32                   DumpReasonParameter3;
  UINT32                   DumpReasonParameter4;

  //
  // Dump flags. Should not include DUMP_VALID, INSUFFICIENT_STORAGE, or
  // IS_HYPERV_DATA_PROTECTED.
  //
  RAW_DUMP_HEADER_FLAGS    Flags;

  //
  // Reserved. Must be set to NULL.
  // Potential future use: Secure-Kernel redaction information.
  //
  VOID                     *Reserved;
} OFFLINE_DUMP_PROVIDER_DUMP_INFO;

/**
  Called by the collector when it is about to begin writing the dump. The provider
  uses this function to initialize any state needed for the dump,
  identify the revision of the collector, and provide information about the dump to
  the collector.

  @param[in]   pThis              A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in]   CollectorInfoSize  The size of the pCollectorInfo buffer (i.e.
                                  sizeof(OFFLINE_DUMP_COLLECTOR_INFO) when the collector was
                                  compiled). The provider should not read more than
                                  this many bytes from the buffer.
  @param[in]   pCollectorInfo     A pointer to a buffer that contains Collector information
                                  (information that the collector provides to the protocol).
  @param[in]   DumpInfoSize       The size of the pDumpInfo buffer (i.e.
                                  sizeof(OFFLINE_DUMP_PROVIDER_DUMP_INFO) when the collector was
                                  compiled). The provider should not write more than
                                  this many bytes to the buffer.
  @param[out]  pDumpInfo          A pointer to a buffer that receives the dump information
                                  (information that the protocol returns to the collector).

  @returns                        EFI_SUCCESS if the dump information was successfully written to
                                  pDumpInfo. An error code if the dump information could not be
                                  written to pDumpInfo (collector will fail writing the dump, will not
                                  invoke the End method, and will return the specified error).
**/
typedef
  EFI_STATUS
(EFIAPI *OFFLINE_DUMP_PROVIDER_BEGIN)(
                                      IN  OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                      IN  UINTN CollectorInfoSize,
                                      IN  OFFLINE_DUMP_COLLECTOR_INFO const *pCollectorInfo,
                                      IN  UINTN DumpInfoSize,
                                      OUT OFFLINE_DUMP_PROVIDER_DUMP_INFO *pDumpInfo
                                      );

/**
  Called by the collector every few seconds to report on dump progress.

  TODO: Do we really need this to return an error code?

  The provider uses this function to update UI to reflect dump progress.
  For example, the provider might update a progress bar or blink an LED.

  @param[in]   pThis          A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in]   ExpectedBytes  The total number of bytes expected to be written.
  @param[in]   WrittenBytes   The number of bytes written so far.

  @returns                    EFI_SUCCESS if the collector should continue writing the dump.
                              An error code if the collector should stop writing and return the
                              specified error.

**/
typedef
  EFI_STATUS
(EFIAPI *OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS)(
                                                IN OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                                IN UINT64 ExpectedBytes,
                                                IN UINT64 WrittenBytes
                                                );

/**
  Called by the collector when it has finished writing the dump. The provider
  uses this function to clean up any state needed for the dump
  and to process the success/failure of the dump.

  @param[in] pThis   A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in] Status  EFI_SUCCESS if the dump was successfully written. An error code otherwise.

**/
typedef
  VOID
(EFIAPI *OFFLINE_DUMP_PROVIDER_END)(
                                    IN  OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                    IN  EFI_STATUS Status
                                    );

struct _OFFLINE_DUMP_PROVIDER_PROTOCOL {
  OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION    Revision;
  OFFLINE_DUMP_PROVIDER_BEGIN                Begin;          // Revision_1_0
  OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS      ReportProgress; // Revision_1_0
  OFFLINE_DUMP_PROVIDER_END                  End;            // Revision_1_0
};

// {56B79CF2-9D1F-42FC-B45A-16BBBA5C623A}
extern EFI_GUID  gOfflineDumpProviderProtocolGuid;

#endif // _included_Protocol_OfflineDumpProvider_h
