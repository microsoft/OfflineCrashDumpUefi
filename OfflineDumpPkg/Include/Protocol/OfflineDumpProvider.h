/** @file
  Microsoft Offline Dump provider protocol - implemented by platform ISV.

  The ISV implements this protocol to provide dump information to the
  Offline Crash Dump writer and to configure writer behavior.

  - OFFLINE_DUMP_PROVIDER_BEGIN (function pointer)
  - OFFLINE_DUMP_PROVIDER_BEGIN_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_DATA_COPY (function pointer)
  - OFFLINE_DUMP_PROVIDER_DUMP_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_DUMP_OPTIONS (struct)
  - OFFLINE_DUMP_PROVIDER_END (function pointer)
  - OFFLINE_DUMP_PROVIDER_END_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_PROTOCOL (struct)
  - OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION (enum)
  - OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS (function pointer)
  - OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_SECTION_INFO (struct)
  - OFFLINE_DUMP_PROVIDER_SECTION_OPTIONS (struct)
  - OFFLINE_DUMP_PROVIDER_SECTION_TYPE (enum)
  - OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64 (struct)
  - OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_X64 (struct)
  - OFFLINE_DUMP_PROVIDER_SECURE_CONTROL (enum)
**/

#ifndef _included_Protocol_OfflineDumpProvider_h
#define _included_Protocol_OfflineDumpProvider_h

#include <Uefi/UefiBaseType.h>
#include <Guid/OfflineDumpConfig.h>     // OFFLINE_DUMP_USE_CAPABILITY_FLAGS
#include <Guid/OfflineDumpEncryption.h> // OFFLINE_MEMORY_DUMP_ENCRYPTION_ALGORITHM
#include <Guid/OfflineDumpHeaders.h>    // FLAGS, ARCHITECTURE, SECTION_INFORMATION

// {56B79CF2-9D1F-42FC-B45A-16BBBA5C623A}
#define OFFLINE_DUMP_PROVIDER_PROTOCOL_GUID \
  { 0x56b79cf2, 0x9d1f, 0x42fc, { 0xb4, 0x5a, 0x16, 0xbb, 0xba, 0x5c, 0x62, 0x3a } }

/**
  Protocol implemented by platform ISV to provide dump information to the Offline
  Crash Dump Writer (OfflineDumpWrite) and to configure Writer behavior.

When OfflineDumpWrite is invoked as a function:

  - ISV implements this protocol.
  - ISV invokes OfflineDumpWrite, passing a pointer to the protocol.
    - OfflineDumpWrite calls the protocol's Begin function to get dump parameters.
    - OfflineDumpWrite writes the dump data, periodically calling the protocol's ReportProgress function.
    - OfflineDumpWrite calls the protocol's End function, providing status and statistics.
    - OfflineDumpWrite returns status.
  - ISV updates dump status variables and reboots.

When OfflineDumpWrite.efi is invoked as an application:

  - ISV implements this protocol.
  - ISV invokes an OfflineDumpWriteExecute helper, passing a pointer to the protocol
    and the path to the OfflineDumpWrite.efi application binary.
    - OfflineDumpWriteExecute installs the protocol instance into the EFI handle table.
    - OfflineDumpWriteExecute loads and starts the OfflineDumpWrite.efi application.
    - OfflineDumpWrite.efi calls the protocol's Begin function to get dump parameters.
    - OfflineDumpWrite.efi writes the dump data, periodically calling the protocol's ReportProgress function.
    - OfflineDumpWrite.efi calls the protocol's End function, providing status and statistics.
    - OfflineDumpWrite returns status.
    - OfflineDumpWriteExecute returns status.
  - ISV updates dump status variables and reboots.

**/
typedef struct _OFFLINE_DUMP_PROVIDER_PROTOCOL OFFLINE_DUMP_PROVIDER_PROTOCOL;

/**
  Revision of the OFFLINE_DUMP_PROVIDER_PROTOCOL interface that a component supports.

  The protocol implementation (provider) specifies its revision in the Revision field
  of the OFFLINE_DUMP_PROVIDER_PROTOCOL structure. The writer uses this value to
  determine which fields of the protocol structure can be accessed. It will never access
  fields that were added in a later revision and will use a default value instead
  (typically NULL or 0).

  The writer implementation specifies its revision value when calling the Begin
  function. The provider uses this value to determine which features the
  writer supports. For example, if a new section type is added in a future version of the
  specification, the provider can use the revision value to determine whether
  the new section type will be recognized.

**/
typedef enum {
  OfflineDumpProviderProtocolRevision_1_0     = 0x00010000,
  OfflineDumpProviderProtocolRevision_Current = OfflineDumpProviderProtocolRevision_1_0,
} OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION) == 4,
               "OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION should be 4 bytes"
               );

/**
  Value that reflects any restriction that the high-level operating system (typically the
  trusted OS) has placed on the dump writer's behavior. This enumeration is used in the
  SecureControl field of the OFFLINE_DUMP_PROVIDER_DUMP_INFO structure.
**/
typedef enum {
  //
  // This value indicates that the high-level operating system has prohibited generation
  // of offline dumps. For example, the high-level OS might set this value if it has
  // started a trusted OS kernel, has secrets in memory that it does not want to be
  // written to the dump, and has not yet configured dump redaction.
  //
  // If this value is specified, the dump writer will not write a dump and will
  // return an error.
  //
  OfflineDumpProviderSecureControl_DumpNotAllowed,

  //
  // This value indicates that the high-level operating system has not placed any
  // restrictions on dump generation. Typically this means that the high-level OS has not
  // started a trusted OS and that no secure-kernel secrets are expected to be in memory.
  //
  // This is the default value (the value that the writer should use if the high-level
  // OS has not set any restrictions).
  //
  // If this value is specified, the dump writer will ignore the
  // SecureConfiguration field and will not attempt to redact any
  // secure-kernel data from the dump.
  //
  OfflineDumpProviderSecureControl_DumpAllowed,

  //
  // This value indicates that the high-level operating system allows an offline dump
  // only if secure-kernel data is redacted from the dump. For example, the high-level
  // OS might set this value if it has started a trusted OS kernel, has secrets in memory
  // that it does not want to be written to the dump, and has successfully configured
  // dump redaction.
  //
  // If this value is specified, the dump writer will use the
  // SecureConfiguration field to determine how to redact secure-kernel
  // data from the dump. If the SecureConfiguration field does not provide
  // valid configuration data, the dump writer will not write the dump and will
  // return an error.
  //
  OfflineDumpProviderSecureControl_RedactedDumpAllowed,
} OFFLINE_DUMP_PROVIDER_SECURE_CONTROL;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_SECURE_CONTROL) == 4,
               "OFFLINE_DUMP_PROVIDER_SECURE_CONTROL should be 4 bytes"
               );

/**
  Type of the section provided by the provider.

  This enumeration type is used in the OFFLINE_DUMP_PROVIDER_SECTION_INFO structure to
  indicate the type of the section being specified. The writer uses this value to determine
  how to process the section when generating a dump.

  This is not always the same as the RAW_DUMP_SECTION_TYPE enumeration. At present,
  OfflineDumpProviderSectionType_DdrRange maps closely to RAW_DUMP_SECTION_DDR_RANGE and
  OfflineDumpProviderSectionType_SvSpecific maps closely to RAW_DUMP_SECTION_SV_SPECIFIC, but
  future OFFLINE_DUMP_PROVIDER_SECTION_TYPE values may not always have a direct mapping to
  RAW_DUMP_SECTION_TYPE values.
**/
typedef enum {
  //
  // Invalid section type.
  //
  OfflineDumpProviderSectionType_None = 0,

  //
  // DDR range section. This section describes a range of DDR memory. This maps closely to
  // RAW_DUMP_SECTION_DDR_RANGE.
  //
  // Implies the following:
  //
  // - The data will generally be written to the dump as a RAW_DUMP_SECTION_DDR_RANGE section
  //   unless it contains non-VTL0 memory, in which case it may be redacted or split into multiple
  //   sections.
  // - The DdrRange variant of the Information union should be used.
  // - The section's name should start with "DDR".
  //
  OfflineDumpProviderSectionType_DdrRange,

  //
  // SV-specific section. This section vendor-defined data. This maps closely to
  // RAW_DUMP_SECTION_SV_SPECIFIC.
  //
  // Implies the following:
  //
  // - The data will be written to the dump as a RAW_DUMP_SECTION_SV_SPECIFIC section.
  // - The SVSpecific variant of the Information union should be used.
  //
  OfflineDumpProviderSectionType_SvSpecific,
} OFFLINE_DUMP_PROVIDER_SECTION_TYPE;

/**
  Callback used for reading the section data, e.g. to access fenced memory regions.
  Used in the OFFLINE_DUMP_PROVIDER_SECTION_INFO structure's DataCopyCallback field.

  @param[in]  pDataStart      The value of the opaque pDataStart parameter that was set in
                              OFFLINE_DUMP_PROVIDER_SECTION_INFO.
  @param[in]  Offset          Offset into the section. This will always be less than the DataSize
                              parameter that was set in OFFLINE_DUMP_PROVIDER_SECTION_INFO.
                              This will always be a multiple of 16.
  @param[in]  Size            Number of bytes to read. Offset + Size will always be less than or
                              equal to the DataSize parameter that was set in
                              OFFLINE_DUMP_PROVIDER_SECTION_INFO. Size will always be a
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
(EFIAPI *OFFLINE_DUMP_PROVIDER_DATA_COPY)(
                                          IN VOID const *pDataStart,
                                          IN UINTN      Offset,
                                          IN UINTN      Size,
                                          OUT UINT8     *pDestinationPos
                                          );

/**
  Information from the writer that is passed to the provider's Begin function.

  The writer provides this information to the protocol implementation (provider) when calling the
  Begin function. The provider uses this information to configure its behavior.

  If the writer and the provider are compiled against different revisions of the
  protocol, they may disagree on the size of this structure. The provider's Begin
  function should only read the first BeginInfoSize bytes of the pBeginInfo buffer. One way
  to handle this is to use a copy of the structure. For example, the Begin function might have
  code like this:

    OFFLINE_DUMP_PROVIDER_BEGIN_INFO BeginInfoCopy = { 0 };
    CopyMem(&BeginInfoCopy, pBeginInfo, MIN(sizeof(BeginInfoCopy), BeginInfoSize));
    // ... Use BeginInfoCopy rather than reading from pBeginInfo ...
**/
typedef struct {
  //
  // The revision of the writer that is calling this function.
  //
  // The protocol implementation (provider) uses this value to determine which features the
  // writer supports. For example, if a new section type is added in a future version of the
  // specification, the provider can use the revision value to determine whether
  // the new section type will be recognized by the current version of the writer.
  //
  OFFLINE_DUMP_PROVIDER_PROTOCOL_REVISION    WriterRevision;

  //
  // The capability flags that are requested by the high-level operating system.
  //
  OFFLINE_DUMP_USE_CAPABILITY_FLAGS          UseCapabilityFlags;
} OFFLINE_DUMP_PROVIDER_BEGIN_INFO;

/**
  Information from the writer that is passed to the provider's ReportProgress function.

  The writer provides this information to the protocol implementation (provider) when calling the
  ReportProgress function.

  If the writer and the provider are compiled against different revisions of the
  protocol, they may disagree on the size of this structure. The provider's ReportProgress
  function should only read the first ProgressInfoSize bytes of the pProgressInfo buffer. One way
  to handle this is to use a copy of the structure. For example, the Progress function might have
  code like this:

    OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS_INFO ProgressInfoCopy = { 0 };
    CopyMem(&ProgressInfoCopy, pProgressInfo, MIN(sizeof(ProgressInfoCopy), ProgressInfoSize));
    // ... Use ProgressInfoCopy rather than reading from pProgressInfo ...
**/
typedef struct {
  // The total number of bytes expected to be written.
  UINT64    ExpectedBytes;

  // The number of bytes written so far.
  UINT64    WrittenBytes;
} OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS_INFO;

/**
  Information from the writer that is passed to the provider's End function.

  The writer provides this information to the protocol implementation (provider) when calling the
  End function.

  If the writer and the provider are compiled against different revisions of the
  protocol, they may disagree on the size of this structure. The provider's End
  function should only read the first EndInfoSize bytes of the pEndInfo buffer. One way
  to handle this is to use a copy of the structure. For example, the End function might have
  code like this:

    OFFLINE_DUMP_PROVIDER_END_INFO EndInfoCopy = { 0 };
    CopyMem(&EndInfoCopy, pEndInfo, MIN(sizeof(EndInfoCopy), EndInfoSize));
    // ... Use EndInfoCopy rather than reading from pEndInfo ...
**/
typedef struct {
  //
  // EFI_SUCCESS if the dump was successfully written. An error code otherwise.
  // Note that if OfflineDumpWrite calls End(Status), OfflineDumpWrite will
  // always return the same Status.
  //
  EFI_STATUS            Status;

  //
  // The encryption algorithm that was used for full-dump encryption, or NONE if not encrypted.
  //
  ENC_DUMP_ALGORITHM    EncryptionAlgorithm;

  //
  // The amount of storage space available for the dump.
  //
  UINT64                SizeAvailable;

  //
  // The amount of storage space required for the dump.
  //
  // This may be greater than SizeAvailable, indicating that the dump was truncated.
  //
  UINT64                SizeRequired;
} OFFLINE_DUMP_PROVIDER_END_INFO;

/**
  Information used to perform redaction of secure-kernel CPU context information for
  ARM64. This structure is used in the pSecureCpuContexts field of
  OFFLINE_DUMP_PROVIDER_DUMP_INFO.
*/
typedef struct {
  UINT64 TTBR1_EL1; // Translation Table Base Register 1 (EL1)
} OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64;

/**
  Information used to perform redaction of secure-kernel CPU context information for
  X64. This structure is used in the pSecureCpuContexts field of
  OFFLINE_DUMP_PROVIDER_DUMP_INFO.
*/
typedef struct {
  UINT64 Reserved1; // Reserved
} OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_X64;

/**
  Information provided by the protocol implementation (provider) to the writer to control
  writer behavior. This information is provided in the Options field of
  OFFLINE_DUMP_PROVIDER_DUMP_INFO.
**/
typedef struct {
  //
  // Maximum total bytes to allocate for the dump writer's I/O buffers (soft limit). If
  // this is 0, the writer will select a reasonable default.
  //
  // - If BufferMemoryLimit == 0 then ActualBufferMemoryLimit will be set to a default
  //   value (currently 3MB).
  // - Else if BufferMemoryLimit < BlockSize * ActualBufferCount then
  //   ActualBufferMemoryLimit will be set to BlockSize * ActualBufferCount.
  // - Else ActualBufferMemoryLimit will be set to BufferMemoryLimit.
  //
  // This value is used to determine
  // ActualBufferSize = RoundDownToBlockSize(ActualBufferMemoryLimit / ActualBufferCount).
  //
  // Note that this does not cap total memory usage of the writer. The dump writer also
  // allocates several other buffers, e.g. it allocates SectionCount * 64 bytes to track
  // section headers.
  //
  UINT32    BufferMemoryLimit;

  //
  // Number of data buffers to use for async I/O. Significant only if the device supports
  // async I/O (EFI_BLOCK_IO2_PROTOCOL). If this is 0, the writer will select a
  // reasonable default.
  //
  // Current implementation:
  //
  // - If the device only supports EFI_BLOCK_IO_PROTOCOL or if DisableBlockIo2 is TRUE
  //   then ActualBufferCount will be set to 1.
  // - Else if BufferCount == 0 then ActualBufferCount will be set to a default (currently 3).
  // - Else if BufferCount < 2 then ActualBufferCount will be set to 2.
  // - Else ActualBufferCount will be set to BufferCount.
  //
  UINT32    BufferCount : 8;

  //
  // If TRUE, the writer will use EFI_BLOCK_IO_PROTOCOL (synchronous I/O) even if the
  // device supports EFI_BLOCK_IO2_PROTOCOL. Set this to improve performance if a
  // device implements the BLOCK_IO2 protocol but does not actually implement async
  // operations, e.g. the EDK2 ATA driver.
  //
  // Implementation detail: in addition to forcing the use of EFI_BLOCK_IO_PROTOCOL, this
  // flag also affects how the writer manages buffers. Since the device does not support
  // async I/O, the writer will allocate one large buffer instead of several smaller buffers.
  //
  UINT32    DisableBlockIo2  : 1;

  //
  // For testing/debugging purposes.
  //
  // If TRUE, the writer will not set the DUMP_VALID flag when finalizing the dump.
  //
  UINT32    ForceDumpInvalid : 1;

  //
  // For testing/debugging purposes. Production environment MUST NOT set this flag.
  //
  // If TRUE, the writer will ignore the full-dump encryption UEFI variables and will
  // always produce an unencrypted dump.
  //
  UINT32    ForceUnencrypted : 1;

  //
  // For testing/debugging purposes. Production environment MUST NOT set this flag.
  //
  // If TRUE, the writer will ignore the SecureControl field and will
  // behave as if SecureControl == OfflineDumpProviderSecureControl_DumpAllowed.
  //
  UINT32    ForceDumpAllowed : 1;

  //
  // Reserved - must be set to 0.
  //
  UINT32    Reserved1        : 20;
} OFFLINE_DUMP_PROVIDER_DUMP_OPTIONS;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_DUMP_OPTIONS) == 8,
               "OFFLINE_DUMP_PROVIDER_DUMP_OPTIONS should be 8 bytes"
               );

/**
  Information provided by the protocol implementation (provider) to the writer to control section
  behavior. This information is provided in the Options field of OFFLINE_DUMP_PROVIDER_SECTION_INFO.
**/
typedef struct {
  //
  // Normally FALSE. If TRUE, indicates that the writer should not set the DUMP_VALID flag
  // for the section.
  //
  UINT32    ForceSectionInvalid : 1;

  //
  // Reserved - must be set to 0.
  //
  UINT32    Reserved1           : 31;

  //
  // Reserved - must be set to 0.
  //
  UINT32    Reserved2;
} OFFLINE_DUMP_PROVIDER_SECTION_OPTIONS;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_SECTION_OPTIONS) == 8,
               "OFFLINE_DUMP_PROVIDER_SECTION_OPTIONS should be 8 bytes"
               );

/**
  Information provided by the protocol implementation (provider) to the writer about a section to be included
  in the dump. This information is provided in the pSections field of OFFLINE_DUMP_PROVIDER_DUMP_INFO.

  Note that in some cases, a single OFFLINE_DUMP_PROVIDER_SECTION_INFO element may result in
  multiple sections being written to the dump, or it may be ignored entirely. For example:

  - A single DdrRange section may result in multiple DDR sections being written to the dump, e.g. if
    parts of the section contain secure-kernel data and need to be encrypted.
  - If the writer does not support the specified section, it will ignore the section and will not write
    it to the dump.
**/
typedef struct {
  //
  // Configuration options for the section. Usually the default (0) values are ok.
  //
  OFFLINE_DUMP_PROVIDER_SECTION_OPTIONS    Options;

  //
  // Section type, e.g. DdrRange or SvSpecific.
  //
  OFFLINE_DUMP_PROVIDER_SECTION_TYPE       Type;

  //
  // Normally NONE. Should not include DUMP_VALID or INSUFFICIENT_STORAGE.
  //
  RAW_DUMP_SECTION_HEADER_FLAGS            Flags;

  //
  // Section name. Ends at first '\0', or at 20 chars.
  // If this is set to NULL or "" then the writer will generate a default name like
  // "DDR-004.bin" for the section.
  //
  // Section names should be unique and should be valid NTFS file names (not checked).
  // DdrRange section names should start with "DDR".
  //
  CHAR8 const                     *pName;

  //
  // Additional information about the section. The format of this information depends on the
  // section type. For example, if Type=DdrRange, the Information.DdrRange field of the union
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
  // If DataCopyCallback == NULL, the writer will treat pDataStart as a pointer to normal readable memory
  // and will access it directly. (Preferred - this allows the writer to optimize the data copy.)
  //
  // If DataCopyCallback != NULL, the writer will treat pDataStart as an opaque context value and will call
  // DataCopyCallback as needed to read the section data. This might be used for data that is
  // generated/filtered on-the-fly or for data that is copied by a co-processor from a fenced region.
  //
  OFFLINE_DUMP_PROVIDER_DATA_COPY    DataCopyCallback;

  //
  // Must be set to NULL. (Potential future use: extended section configuration.)
  //
  VOID const                         *Reserved1;
} OFFLINE_DUMP_PROVIDER_SECTION_INFO;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_PROVIDER_SECTION_INFO) == 72,
               "OFFLINE_DUMP_PROVIDER_SECTION_INFO should be 72 bytes"
               );

/**
  Dump configuration information returned to the writer by the provider's
  Begin function.

  If the writer and the provider are compiled against different revisions of the
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
  // Configuration options for the writer, including options for adjusting the I/O
  // buffer allocation (for tuning I/O performance and memory usage). Usually the default
  // (0) values are ok.
  //
  OFFLINE_DUMP_PROVIDER_DUMP_OPTIONS    Options;

  //
  // The block device to which the dump should be written, or NULL for default device.
  //
  // If set to non-NULL, the writer will use the specified device. The device must implement
  // EFI_BLOCK_IO2_PROTOCOL (preferred) or EFI_BLOCK_IO_PROTOCOL. Normally the device is the
  // handle of a partition, not the handle of a physical device. The dump will be written
  // directly to this device, starting at LBA 0 (no filesystem is involved).
  //
  // If set to NULL, the writer will attempt to locate an appropriate device, guided by the
  // value of the OfflineMemoryDumpUseCapability UEFI variable. If the writer is unable to
  // find an appropriate device, the writer will fail to write a dump and will end the dump
  // with status EFI_NOT_FOUND.
  //
  EFI_HANDLE    BlockDevice;

  //
  // Pointer to an OFFLINE_DUMP_PROVIDER_SECTION_INFO[SectionCount] array with the
  // information for DdrRange and SvSpecific sections to be included in the dump.
  //
  // This should not include CPU_CONTEXT, DUMP_REASON, or SYSTEM_INFORMATION sections.
  // The writer will automatically add these sections based on the information provided
  // below.
  //
  OFFLINE_DUMP_PROVIDER_SECTION_INFO const    *pSections;

  //
  // Number of elements in the pSections array.
  //
  UINT32                                      SectionCount;

  //
  // Indicates the CPU architecture of the system. This is used in the generated
  // CPU_CONTEXT and SYSTEM_INFORMATION sections.
  //
  RAW_DUMP_ARCHITECTURE                       Architecture;

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
  // This must be a multiple of 8 (alignment for 64-bit registers).
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
  UINT32                   DumpReasonParameters[4];

  //
  // Dump flags. Should not include DUMP_VALID, INSUFFICIENT_STORAGE, or
  // IS_HYPERV_DATA_PROTECTED.
  //
  RAW_DUMP_HEADER_FLAGS    Flags;

  //
  // Reserved (padding to multiple of 8 bytes). Must be set to 0.
  //
  UINT32                   Reserved1;

  //
  // Set to the address of a buffer containing secure kernel configuration data from
  // the high-level operating system. This is used to redact secure-kernel secrets
  // when generating the offline dump.
  //
  // This value should be obtained from trusted firmware.
  // The firmware should provide a CSRT "Offline Dump Capabilities" entry. The entry
  // includes a "Configuration SMC ID" and a "Control SMC ID". If the high-level OS
  // requires offline dump redaction, it will invoke the  SMCs to apply the necessary
  // restrictions.
  //
  // - Trusted firmware should store pOfflineDumpSecureConfiguration and
  //   OfflineDumpSecureConfigurationSize variables in secure (fenced) memory. The values
  //   should be initialized to { NULL, 0 }.
  // - The high-level OS may invoke the "Offline Dump Configuration" SMC to change the
  //   value of the variables. The SMC handler should update its stored value
  //   accordingly.
  // - If a crash occurs, the firmware should save the referenced buffer
  //   so that it can be used during offline dump generation. During generation,
  //   the variable values from trusted firmware are used to set the
  //   pSecureConfiguration and SecureConfigurationSize fields.
  //
  VOID const    *pSecureConfiguration;

  //
  // Size of the secure offline dump configuration data provided by the OS via SMC, or
  // 0 if none.
  //
  UINT32        SecureConfigurationSize;

  //
  // Set to a value indicating any restrictions that the high-level operating system has
  // placed on the dump writer's behavior.
  //
  // This value should be obtained from trusted firmware.
  // The firmware should provide a CSRT "Offline Dump Capabilities" entry. The entry
  // includes a "Configuration SMC ID" and a "Control SMC ID". If the high-level OS
  // requires offline dump redaction, it will invoke the  SMCs to apply the necessary
  // restrictions.
  //
  // - Trusted firmware should store an OfflineDumpSecureControl variable in secure (fenced)
  //   memory. The value should be initialized to OfflineDumpProviderSecureControl_DumpAllowed (1).
  // - The high-level OS may invoke the "Offline Dump Control" SMC to change the value
  //   of the OfflineDumpSecureControl variable. The SMC handler should update its stored value
  //   accordingly.
  // - If a crash occurs, the firmware should save the value of the OfflineDumpSecureControl
  //   variable so that it can be used during offline dump generation. During generation,
  //   the variable value from trusted firmware is used to set the SecureControl
  //   field.
  //
  // This value MUST reflect the true state of the high-level operating system's restrictions.
  // In a debug scenario where the high-level operating system's restrictions need to be
  // ignored, use the ForceDumpAllowed option instead of setting this field to an inaccurate
  // value.
  //
  // The writer uses this value to determine how to redact secure-kernel CPU and memory.
  //
  // - If the ForceDumpAllowed option is set, the writer will ignore this field and will
  //   write the dump with no redaction.
  // - If the ForceDumpAllowed option is unset and this value is set to Allowed, the
  //   writer will generate an unredacted dump.
  // - If the ForceDumpAllowed option is unset and this value is set to RedactedDumpAllowed,
  //   the writer will generate a redacted dump using the pSecureConfiguration
  //   field to determine how to redact secure-kernel CPU and memory. If the
  //   pSecureConfiguration field is NULL or invalid, the writer will not write
  //   the dump and will return an error.
  // - If the ForceDumpAllowed option is unset and this value is set to any other value, the
  //   writer will not generate a dump and will return an error.
  //
  OFFLINE_DUMP_PROVIDER_SECURE_CONTROL    SecureControl;

  //
  // Pointer to an array of secure context structures, one for each core on the
  // system. Core contexts must be ordered the same way as in the pCpuContexts
  // field (i.e. SecureCpuContexts[N] must be the secure context for the core
  // described by CpuContexts[N]).
  //
  // This field is used when performing CPU context redaction.
  //
  // - If Architecture == RAW_DUMP_ARCHITECTURE_ARM64, this should point at an
  //   OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64[SecureCpuContextCount] array.
  // - If Architecture == RAW_DUMP_ARCHITECTURE_X64, this should point at an
  //   OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_X64[SecureCpuContextCount] array.
  //
  VOID const    *pSecureCpuContexts;

  //
  // Number of elements in the pSecureCpuContexts array (number of cores on the system).
  // This should be the same as the CpuContextCount field.
  //
  UINT32        SecureCpuContextCount;

  //
  // The size of each element in the pSecureCpuContexts array.
  // This must be a multiple of 8 (alignment for 64-bit registers).
  //
  // - If Architecture == RAW_DUMP_ARCHITECTURE_ARM64, this should be sizeof(OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64).
  // - If Architecture == RAW_DUMP_ARCHITECTURE_X64, this should be sizeof(OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_X64).
  //
  UINT32        SecureCpuContextSize;
} OFFLINE_DUMP_PROVIDER_DUMP_INFO;

/**
  Called by the writer when it is about to begin writing the dump. The provider
  uses this function to identify the revision of the writer, initialize any state needed
  for the dump, and provide information about the dump to the writer.

  @param[in]   pThis              A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in]   BeginInfoSize      The size of the pBeginInfo buffer (i.e.
                                  sizeof(OFFLINE_DUMP_PROVIDER_BEGIN_INFO) when the writer was
                                  compiled). The provider should not read more than
                                  this many bytes from the buffer.
  @param[in]   pBeginInfo         A pointer to a buffer that contains information that the
                                  writer provides to the protocol).
  @param[in]   DumpInfoSize       The size of the pDumpInfo buffer (i.e.
                                  sizeof(OFFLINE_DUMP_PROVIDER_DUMP_INFO) when the writer was
                                  compiled). The provider should not write more than
                                  this many bytes to the buffer.
  @param[out]  pDumpInfo          A pointer to a buffer that receives the dump information
                                  (information that the protocol returns to the writer).

  @returns                        EFI_SUCCESS if the dump information was successfully written to
                                  pDumpInfo. An error code if the dump information could not be
                                  written to pDumpInfo (writer will fail writing the dump, will not
                                  invoke the End method, and will return the specified error).
**/
typedef
  EFI_STATUS
(EFIAPI *OFFLINE_DUMP_PROVIDER_BEGIN)(
                                      IN  OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                      IN  UINTN BeginInfoSize,
                                      IN  OFFLINE_DUMP_PROVIDER_BEGIN_INFO const *pBeginInfo,
                                      IN  UINTN DumpInfoSize,
                                      OUT OFFLINE_DUMP_PROVIDER_DUMP_INFO *pDumpInfo
                                      );

/**
  Called by the writer every few seconds to report on dump progress.

  The provider uses this function to update UI to reflect dump progress.
  For example, the provider might update a progress bar or blink an LED.

  @param[in]   pThis            A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in]   ProgressInfoSize The size of the pProgressInfo buffer (i.e.
                                sizeof(OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS_INFO) when the writer was
                                compiled). The provider should not read more than
                                this many bytes from the buffer.
  @param[in]   pProgressInfo    A pointer to a buffer that contains information that the
                                writer provides to the protocol).

  @returns                      EFI_SUCCESS if the writer should continue writing the dump.
                                An error code if the writer should stop writing and return the
                                specified error.

**/
typedef
  EFI_STATUS
(EFIAPI *OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS)(
                                                IN OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                                IN  UINTN ProgressInfoSize,
                                                IN  OFFLINE_DUMP_PROVIDER_REPORT_PROGRESS_INFO const *pProgressInfo
                                                );

/**
  Called by the writer when it has finished writing the dump.
  This will be called if and only if the Begin function returned EFI_SUCCESS.

  The provider uses this function to clean up any actions performed by Begin.
  It may also record the status of the dump.

  @param[in] pThis         A pointer to the OFFLINE_DUMP_PROVIDER_PROTOCOL instance.
  @param[in]   EndInfoSize The size of the pEndInfo buffer (i.e.
                           sizeof(OFFLINE_DUMP_PROVIDER_END_INFO) when the writer was
                           compiled). The provider should not read more than
                           this many bytes from the buffer.
  @param[in]   pEndInfo    A pointer to a buffer that contains information that the
                           writer provides to the protocol).

**/
typedef
  VOID
(EFIAPI *OFFLINE_DUMP_PROVIDER_END)(
                                    IN  OFFLINE_DUMP_PROVIDER_PROTOCOL *pThis,
                                    IN  UINTN EndInfoSize,
                                    IN  OFFLINE_DUMP_PROVIDER_END_INFO const *pEndInfo
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
