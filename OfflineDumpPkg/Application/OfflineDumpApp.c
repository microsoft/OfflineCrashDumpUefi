#include <OfflineDumpWriter.h>          // OFFLINE_DUMP_WRITER
#include <OfflineDumpPartition.h>       // FindOfflineDumpPartitionHandle
#include <OfflineDumpVariables.h>       // GetVariableOfflineMemoryDumpUseCapability
#include <Guid/OfflineDumpCpuContext.h> // CONTEXT_AMD64, CONTEXT_ARM64

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

/*
IMPORTANT: The DUMP_WRITER class is a preliminary interface and will be changed in a future release.

At present, the DUMP_WRITER class is the supported API for writing offline dump files. It is used as:

- writer = DumpWriterOpen(NumberOfSections, options...);
- For NumberOfSections sections: DumpWriterWriteSection(writer, section information...);
- DumpWriterClose(writer);

The DUMP_WRITER class handles block I/O and full-dump encryption, but it does not help with
formatting section data, per-section encryption, redacting SK/Hyper-V memory regions,
redacting SK CPU registers, or other important features.

A future release will replace the DUMP_WRITER class with a new API that supports these features.
The DUMP_WRITER class will become a private implementation detail of the new API. The new API
will be a single WriteDump function that takes a single pOfflineDumpConfigurationProtocol parameter
that points to a data structure with all of the information needed to write a dump file:

- Required: CPU context data to be included in the dump.
- Required: Dump reason data to be included in the dump.
- Required: System information data to be included in the dump.
- Required: List of DDR_RANGE sections to be included in the dump.
- Required: Progress callback (to blink a progress LED or update the screen).
- Optional: Redaction list for Secure Kernel memory.
- Optional: List of other sections to be included in the dump (e.g. SV_SPECIFIC).
- Optional: Custom rules for locating the block device to which the dump should be written.
- Optional: Other customizations, e.g. memory management tuning parameters.
*/

#ifdef __INTELLISENSE__
#define PcdGetBool(x)  TRUE
#endif

// For use in printf format values.
typedef long long unsigned llu_t;

static CHAR8 const * const  HelloSectionName     = "HelloSection";
static CHAR8 const          HelloSectionData[]   = "Hello, World!";
static UINTN const          HelloSectionDataSize = sizeof (HelloSectionData);

// {740A5381-34D6-488d-B03C-A8E6D0181808}
static GUID const  HelloSectionGuid =
{
  0x740a5381, 0x34d6, 0x488d, {
    0xb0,     0x3c,   0xa8,   0xe6, 0xd0, 0x18, 0x18, 0x8
  }
};

// The data for any section can be provided via a callback.
// If the callback is specified as NULL, the data will be copied directly (e.g. via CopyMem).
static EFI_STATUS EFIAPI
CopyCpuContextCallback (
  OUT UINT8      *pDestinationPos,
  IN void const  *pDataStart,
  IN UINTN       Offset,
  IN UINTN       Size
  )
{
  // Callback should perform any custom logic needed to access the section's data,
  // e.g. it could call into a coprocessor to copy the data.
  //
  // In real code, you should not use a callback if you are just performing a normal CopyMem.
  // If you pass NULL as the callback, the writer will perform the copy directly.
  CopyMem (pDestinationPos, (UINT8 *)pDataStart + Offset, Size);
  return EFI_SUCCESS;
}

// Copies up to MaxSize bytes from Source to Destination.
// If Source is not null-terminated, Destination will not be null-terminated.
static void
AsciiStrnCpy (
  OUT CHAR8        *pDestination,
  IN  CHAR8 const  *pSource,
  IN  UINTN        MaxCount
  )
{
  for (UINTN i = 0; i != MaxCount; i += 1) {
    pDestination[i] = pSource[i];
    if (pSource[i] == '\0') {
      return;
    }
  }
}

// If a memory descriptor is a section that should be included in the dump, returns
// the name to be used for the section in the dump. Otherwise, returns NULL.
static CHAR8 const *
MemoryDescriptorToSectionName (
  EFI_MEMORY_DESCRIPTOR const  *Desc
  )
{
  switch (Desc->Type) {
    case EfiConventionalMemory:
      return "ConventionalMemory";
    default:
      return NULL;
  }
}

EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS           Status;
  UINT8                *MemoryMap  = NULL;
  OFFLINE_DUMP_WRITER  *DumpWriter = NULL;

  OFFLINE_DUMP_USE_CAPABILITY_FLAGS  OfflineMemoryDumpUseCapability;

  Status = GetVariableOfflineMemoryDumpUseCapability (&OfflineMemoryDumpUseCapability);
  if (EFI_ERROR (Status)) {
    Print (L"GetVariableOfflineMemoryDumpUseCapability() failed (%r)\n", Status);
    goto Done;
  }

  if (0 == (OfflineMemoryDumpUseCapability & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN)) {
    Print (L"Dump disabled: OfflineMemoryDumpUseCapability = 0x%X.\n", OfflineMemoryDumpUseCapability);
    Status = EFI_SUCCESS;
    goto Done;
  }

  EFI_HANDLE  BlockDeviceHandle;
  Status = PcdGetBool (PcdOfflineDumpUsePartition)
           // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
    ? FindOfflineDumpPartitionHandle (&BlockDeviceHandle)
           // For testing on Emulator: Look for a raw block device that is not a partition.
    : FindOfflineDumpRawBlockDeviceHandleForTesting (&BlockDeviceHandle);
  if (EFI_ERROR (Status)) {
    Print (L"Dump error: FindOfflineDumpPartitionHandle failed (%r)\n", Status);
    goto Done;
  }

  UINTN   MemoryMapSize = 0;
  UINTN   MapKey;
  UINTN   DescriptorSize;
  UINT32  DescriptorVersion;

  Status = gBS->GetMemoryMap (&MemoryMapSize, (EFI_MEMORY_DESCRIPTOR *)MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print (L"GetMemoryMap() failed (%r)\n", Status);
    goto Done;
  }

  MemoryMap = AllocatePool (MemoryMapSize);
  if (MemoryMap == NULL) {
    Print (L"AllocatePool(MemoryMapSize = %u) failed\n", MemoryMapSize);
    goto Done;
  }

  Status = gBS->GetMemoryMap (&MemoryMapSize, (EFI_MEMORY_DESCRIPTOR *)MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR (Status)) {
    Print (L"GetMemoryMap() failed (%r)\n", Status);
    goto Done;
  }

  UINT32  SectionsCount = 0;
  SectionsCount += 1; // SV_SPECIFIC: HelloSection
  SectionsCount += 1; // DUMP_REASON
  SectionsCount += 1; // CPU_CONTEXT
  SectionsCount += 1; // SYSTEM_INFORMATION

  for (UINT8 const *DescPos = MemoryMap; DescPos < MemoryMap + MemoryMapSize; DescPos += DescriptorSize) {
    EFI_MEMORY_DESCRIPTOR const  *Desc        = (EFI_MEMORY_DESCRIPTOR const *)DescPos;
    CHAR8 const                  *SectionName = MemoryDescriptorToSectionName (Desc);
    if (!SectionName) {
      continue;
    }

    SectionsCount += 1; // DDR_RANGE
  }

  OFFLINE_DUMP_WRITER_OPTIONS const  Options = {
    // Set to true if writing to a device that supports BLOCK_IO2_PROTOCOL but doesn't actually
    // support async I/O. This will cause the writer to optimize for synchronous I/O and to use
    // the BlockIo protocol instead of BlockIo2.
    .DisableBlockIo2   = FALSE,

    // This flag exists for testing and should not be TRUE in production.
    // If TRUE, the writer will ignore the OfflineMemoryDumpEncryptionAlgorithm variable.
    .ForceUnencrypted  = FALSE,

    // BufferCount = 0 means use the default (currently 3).
    // You may want to tune this (use the OfflineDumpBench tool to experiment). Please provide
    // feedback on what works best for your system.
    .BufferCount       = 0,

    // BufferMemoryLimit = 0 means use the default (currently 3MB).
    // BufferMemoryLimit = 1 means as small as possible (currently 4KB * BufferCount).
    // You may want to tune this (use the OfflineDumpBench tool to experiment). Please provide
    // feedback on what works best for your system.
    .BufferMemoryLimit = 0,
  };

  Status = OfflineDumpWriterOpen (
                                  BlockDeviceHandle,
                                  // Flags for the dump header, e.g. IS_HYPERV_DATA_PROTECTED, IS_DDR_CACHE_FLUSHED.
                                  // Must not include DUMP_VALID or INSUFFICIENT_STORAGE flags -- they're handled automatically.
                                  RAW_DUMP_HEADER_IS_DDR_CACHE_FLUSHED,
                                  SectionsCount,
                                  &Options,
                                  &DumpWriter
                                  );
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterOpen() failed (%r)\n", Status);
    goto Done;
  }

  // 16-byte value in each section.
  // The usage of this value is different for each section..
  RAW_DUMP_SECTION_INFORMATION  Information;

  // SV_SPECIFIC: HelloSection
  {
    // Your dump may include any number of vendor-specific sections.
    // You may use them for dump information that does not directly come from DDR memory, or
    // for regions that need to be handled specifially (e.g. they need to be encrypted with
    // a vendor-controlled key).

    // For an SV_SPECIFIC section, the vendor defines the meaning of the Information field.
    // You'll typically use this to store a unique identifier so that you can recognize the section later.
    ZeroMem (&Information, sizeof (Information));
    CopyGuid ((GUID *)Information.SVSpecific.SVSpecificData, &HelloSectionGuid);

    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Flags - should include DUMP_VALID flag if section is valid.
                                            // Must not include the INSUFFICIENT_STORAGE flag -- it's handled automatically.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            1, // MajorVersion - defined by vendor.
                                            0, // MinorVersion - defined by vendor.
                                            RAW_DUMP_SECTION_SV_SPECIFIC,
                                            &Information,
                                            HelloSectionName,    // Section naming convention is defined by the vendor.
                                            NULL,                // Use CopyMem instead of a callback.
                                            HelloSectionData,    // Section data content defined by the vendor.
                                            HelloSectionDataSize // Size of the data in the section.
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"WriteSection(HelloSection) failed (%r)\n", Status);
      goto Done;
    }
  }

  // DUMP_REASON
  {
    // Your dump must include exactly one DUMP_REASON section.

    ZeroMem (&Information, sizeof (Information));
    Information.DumpReason.Parameter1 = 0x12345678; // Watson bucketization parameter 1.
    Information.DumpReason.Parameter2 = 0xA;        // Watson bucketization parameter 2.
    Information.DumpReason.Parameter3 = 0x1234;     // Watson bucketization parameter 3.
    Information.DumpReason.Parameter4 = 0x0;        // Watson bucketization parameter 4.

    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Flags - should include DUMP_VALID flag if section is valid.
                                            // Must not include the INSUFFICIENT_STORAGE flag -- it's handled automatically.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            RAW_DUMP_DUMP_REASON_CURRENT_MAJOR_VERSION,
                                            RAW_DUMP_DUMP_REASON_CURRENT_MINOR_VERSION,
                                            RAW_DUMP_SECTION_DUMP_REASON,
                                            &Information,
                                            "DumpReason",
                                            NULL, // Use CopyMem instead of a callback.
                                            NULL, // No data content for this section.
                                            0     // Size of the data in the section.
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"WriteSection(DumpReason) failed (%r)\n", Status);
      goto Done;
    }
  }

  // CPU_CONTEXT
  {
    // Your dump must include exactly one CPU_CONTEXT section.
    CONTEXT_ARM64  Contexts[4] = { 0 };
    for (unsigned i = 0; i < ARRAY_SIZE (Contexts); i += 1) {
      // TODO: Fill in the CPU context data for each core.
      CONTEXT_ARM64  *pContext = &Contexts[i];
      pContext->Pc = 0x1234;
    }

    ZeroMem (&Information, sizeof (Information));
    Information.CpuContext.Architecture = PROCESSOR_ARCHITECTURE_ARM64; // Or PROCESSOR_ARCHITECTURE_AMD64.
    Information.CpuContext.CoreCount    = ARRAY_SIZE (Contexts);
    Information.CpuContext.ContextSize  = sizeof (CONTEXT_ARM64);  // Or sizeof (CONTEXT_AMD64).

    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Flags - should include DUMP_VALID flag if section is valid.
                                            // Must not include the INSUFFICIENT_STORAGE flag -- it's handled automatically.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            RAW_DUMP_CPU_CONTEXT_CURRENT_MAJOR_VERSION,
                                            RAW_DUMP_CPU_CONTEXT_CURRENT_MINOR_VERSION,
                                            RAW_DUMP_SECTION_CPU_CONTEXT,
                                            &Information,
                                            "CpuContext",
                                            CopyCpuContextCallback, // For demonstration purposes: Use a callback instead of CopyMem.
                                            Contexts,               // Pass this value to the callback.
                                            sizeof (Contexts)       // Size of the data in the section.
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"WriteSection(CpuContext) failed (%r)\n", Status);
      goto Done;
    }
  }

  // SYSTEM_INFORMATION
  {
    // Your dump must include exactly one SYSTEM_INFORMATION section.

    ZeroMem (&Information, sizeof (Information));
    AsciiStrnCpy (Information.SystemInformation.Vendor, "VEND", sizeof (Information.SystemInformation.Vendor));         // 4-character vendor ACPI ID.
    AsciiStrnCpy (Information.SystemInformation.Platform, "PLATFORM", sizeof (Information.SystemInformation.Platform)); // 8-character silicon vendor platform ID.
    Information.SystemInformation.Architecture = RAW_DUMP_ARCHITECTURE_ARM64;                                           // Or RAW_DUMP_ARCHITECTURE_X64.

    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Flags - should include DUMP_VALID flag if section is valid.
                                            // Must not include the INSUFFICIENT_STORAGE flag -- it's handled automatically.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            RAW_DUMP_SYSTEM_INFORMATION_CURRENT_MAJOR_VERSION,
                                            RAW_DUMP_SYSTEM_INFORMATION_CURRENT_MINOR_VERSION,
                                            RAW_DUMP_SECTION_SYSTEM_INFORMATION,
                                            &Information,
                                            "SystemInformation",
                                            NULL, // Use CopyMem instead of a callback.
                                            NULL, // No data content for this section.
                                            0     // Size of the data in the section.
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"WriteSection(SystemInformation) failed (%r)\n", Status);
      goto Done;
    }
  }

  for (UINT8 const *DescPos = MemoryMap; DescPos < MemoryMap + MemoryMapSize; DescPos += DescriptorSize) {
    EFI_MEMORY_DESCRIPTOR const  *Desc        = (EFI_MEMORY_DESCRIPTOR const *)DescPos;
    CHAR8 const                  *SectionName = MemoryDescriptorToSectionName (Desc);
    if (!SectionName) {
      continue;
    }

    ZeroMem (&Information, sizeof (Information));
    Information.DdrRange.Base = Desc->PhysicalStart;

    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Flags - should include DUMP_VALID flag if section is valid.
                                            // Must not include the INSUFFICIENT_STORAGE flag -- it's handled automatically.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            RAW_DUMP_DDR_RANGE_CURRENT_MAJOR_VERSION,
                                            RAW_DUMP_DDR_RANGE_CURRENT_MINOR_VERSION,
                                            RAW_DUMP_SECTION_DDR_RANGE,
                                            &Information,
                                            SectionName,
                                            NULL, // Use CopyMem instead of a callback.
                                            (void const *)(UINTN)Desc->PhysicalStart,
                                            EFI_PAGES_TO_SIZE (Desc->NumberOfPages)
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"WriteSection(DdrRange) failed (%r)\n", Status);
      goto Done;
    }
  }

  ASSERT (SectionsCount == OfflineDumpWriterGetDumpHeader (DumpWriter)->SectionsCount);

  EFI_STATUS const  LastError           = OfflineDumpWriterLastWriteError (DumpWriter);
  UINT64 const      MediaPos            = OfflineDumpWriterMediaPosition (DumpWriter);
  UINT64 const      MediaSize           = OfflineDumpWriterMediaSize (DumpWriter);
  BOOLEAN  const    InsufficientStorage = OfflineDumpWriterHasInsufficientStorage (DumpWriter);

  Status     = OfflineDumpWriterClose (DumpWriter, TRUE);
  DumpWriter = NULL;
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterClose() failed (%r)\n", Status);
    goto Done;
  }

  if (LastError != EFI_SUCCESS) {
    Print (L"Last write error: %r\n", LastError);
  }

  if (InsufficientStorage) {
    Print (
           L"Insufficient storage (Have 0x%llX Need 0x%llX)\n",
           (llu_t)MediaSize,
           (llu_t)MediaPos
           );
  }

  if ((LastError != EFI_SUCCESS) || InsufficientStorage) {
    Status = EFI_ABORTED;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:

  if (DumpWriter != NULL) {
    (void)OfflineDumpWriterClose (DumpWriter, FALSE);
  }

  if (MemoryMap != NULL) {
    FreePool (MemoryMap);
  }

  Print (L"Exiting (%r)\n", Status);
  return Status;
}
