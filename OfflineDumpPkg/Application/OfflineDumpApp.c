#include <OfflineDumpLib.h>
#include <Guid/OfflineDumpCpuContext.h> // CONTEXT_AMD64, CONTEXT_ARM64

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

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
static BOOLEAN EFIAPI
CopyHelloDataCallback (
  IN void const  *pDataStart,
  IN UINTN       Offset,
  IN UINTN       Size,
  OUT UINT8      *pDestinationPos
  )
{
  // Callback should perform any custom logic needed to access the section's data,
  // e.g. it could call into a coprocessor to copy the data.
  //
  // In real code, you should not use a callback if you are just performing a normal CopyMem.
  // If you pass NULL as the callback, the writer will perform an optimized copy using CopyMem.
  CopyMem (pDestinationPos, (UINT8 *)pDataStart + Offset, Size);
  return TRUE;
}

typedef struct {

  // Protocol implementation must always start with the protocol interface:

  OFFLINE_DUMP_CONFIGURATION_PROTOCOL              Base;

  // Additional fields needed by the protocol implementation can go here:

  OFFLINE_DUMP_CONFIGURATION_SECTION_INFO const    *pSections;
  UINT32                                           SectionCount;
  RAW_DUMP_ARCHITECTURE                            Architecture;
  VOID const                                       *pCpuContexts;
  UINT32                                           CpuContextCount;
  UINT32                                           CpuContextSize;
  CHAR8 const                                      *pVendor;
  CHAR8 const                                      *pPlatform;
  UINT32                                           DumpReasonParameter1;
  UINT32                                           DumpReasonParameter2;
  UINT32                                           DumpReasonParameter3;
  UINT32                                           DumpReasonParameter4;
  RAW_DUMP_HEADER_FLAGS                            Flags;
} SAMPLE_DUMP_CONFIGURATION_PROTOCOL;

// Simple implementation of the Begin callback for the OfflineDumpConfigurationProtocol.
// This implementation locates the block device to use for the dump, then fills in the remaining
// fields of the DumpInfo structure using data from the protocol instance fields.
static EFI_STATUS
SampleBegin (
  IN  OFFLINE_DUMP_CONFIGURATION_PROTOCOL            *pThisBase,
  IN  UINTN                                          SessionInfoSize,
  IN  OFFLINE_DUMP_CONFIGURATION_SESSION_INFO const  *pSessionInfo,
  IN  UINTN                                          DumpInfoSize,
  OUT OFFLINE_DUMP_CONFIGURATION_DUMP_INFO           *pDumpInfo
  )
{
  EFI_STATUS                          Status;
  SAMPLE_DUMP_CONFIGURATION_PROTOCOL  *pThis = (SAMPLE_DUMP_CONFIGURATION_PROTOCOL *)pThisBase;

  // DumpInfo holds the information we will copy into pDumpInfo.
  OFFLINE_DUMP_CONFIGURATION_DUMP_INFO  DumpInfo = { 0 };

  // SessionInfo holds the information we copy from pSessionInfo.
  OFFLINE_DUMP_CONFIGURATION_SESSION_INFO  SessionInfo = { 0 };

  // In case of size mismatch between the protocol and the writer, copy the smaller of the two.
  CopyMem (&SessionInfo, pSessionInfo, MIN (SessionInfoSize, sizeof (SessionInfo)));

  // Fill in DumpInfo:

  if (0 == (SessionInfo.UseCapabilityFlags & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN)) {
    Print (L"Dump disabled: OfflineMemoryDumpUseCapability = 0x%X.\n", SessionInfo.UseCapabilityFlags);
    Status = EFI_NOT_STARTED;
    goto Done;
  }

  Status = PcdGetBool (PcdOfflineDumpUsePartition)
           // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
           ? FindOfflineDumpPartitionHandle (&DumpInfo.BlockDevice)
           // For testing on X86 Emulator: Look for a raw block device that is not a partition.
           : FindOfflineDumpRawBlockDeviceHandleForTesting (&DumpInfo.BlockDevice);
  if (EFI_ERROR (Status)) {
    Print (L"Dump error: FindOfflineDumpPartitionHandle failed (%r)\n", Status);
    goto Done;
  }

  DumpInfo.pSections            = pThis->pSections;
  DumpInfo.SectionCount         = pThis->SectionCount;
  DumpInfo.Architecture         = pThis->Architecture;
  DumpInfo.pCpuContexts         = pThis->pCpuContexts;
  DumpInfo.CpuContextCount      = pThis->CpuContextCount;
  DumpInfo.CpuContextSize       = pThis->CpuContextSize;
  DumpInfo.pVendor              = pThis->pVendor;
  DumpInfo.pPlatform            = pThis->pPlatform;
  DumpInfo.DumpReasonParameter1 = pThis->DumpReasonParameter1;
  DumpInfo.DumpReasonParameter2 = pThis->DumpReasonParameter2;
  DumpInfo.DumpReasonParameter3 = pThis->DumpReasonParameter3;
  DumpInfo.DumpReasonParameter4 = pThis->DumpReasonParameter4;
  DumpInfo.Flags                = pThis->Flags;

Done:

  // In case of size mismatch between the protocol and the writer, copy the smaller of the two.
  CopyMem (pDumpInfo, &DumpInfo, MIN (DumpInfoSize, sizeof (DumpInfo)));
  Print (L"Begin: %r\n", Status);
  return Status;
}

// Simple implementation of the End callback for the OfflineDumpConfigurationProtocol.
// This will only be called if the Begin callback returns successfully.
// This implementation just prints the status.
// A more complex implementation might perform cleanup or might record the status for later use.
static VOID
SampleEnd (
  IN  OFFLINE_DUMP_CONFIGURATION_PROTOCOL  *pThisBase,
  IN  EFI_STATUS                           Status
  )
{
  (void)pThisBase; // Parameter not used.
  Print (L"End: %r\n", Status);
}

// Simple implementation of the ReportProgress callback for the OfflineDumpConfigurationProtocol.
// This implementation just prints the progress.
// A more complex implementation might update a progress bar or other UI.
static EFI_STATUS
SampleReportProgress (
  IN  OFFLINE_DUMP_CONFIGURATION_PROTOCOL  *pThisBase,
  IN  UINT64                               ExpectedBytes,
  IN  UINT64                               WrittenBytes
  )
{
  (void)pThisBase; // Parameter not used.
  Print (L"ReportProgress: %llu/%llu\n", (llu_t)WrittenBytes, (llu_t)ExpectedBytes);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                               Status;
  UINT8                                    *MemoryMap = NULL;
  OFFLINE_DUMP_CONFIGURATION_SECTION_INFO  *Sections  = NULL;
  OFFLINE_DUMP_CONFIGURATION_SECTION_INFO  *pSection  = NULL;

  UINTN   MemoryMapSize = 0;
  UINTN   MapKey;
  UINTN   DescriptorSize;
  UINT32  DescriptorVersion;

  // Get the memory map.
  // TODO: Real crash dump will probably use a customized memory map to include carve-outs and exclude
  // UEFI boot-time memory.

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

  // Determine the size of the sections array.

  UINT32  SectionsCount = 0;

  // Count one SV_SPECIFIC section (HelloSection for demonstration purposes)
  // TODO: Real crash dump will likely include several SV_SPECIFIC sections.
  SectionsCount += 1;

  // Count the DDR_RANGE sections.
  for (UINT8 const *DescPos = MemoryMap; DescPos < MemoryMap + MemoryMapSize; DescPos += DescriptorSize) {
    EFI_MEMORY_DESCRIPTOR const  *Desc = (EFI_MEMORY_DESCRIPTOR const *)DescPos;
    if (Desc->Type != EfiConventionalMemory) {
      continue;
    }

    SectionsCount += 1; // DDR_RANGE
  }

  // Allocate the sections array.

  Sections = AllocateZeroPool (SectionsCount * sizeof (OFFLINE_DUMP_CONFIGURATION_SECTION_INFO));
  if (Sections == NULL) {
    Print (L"AllocatePool(SectionsCount = %u) failed\n", SectionsCount);
    goto Done;
  }

  // Prepare the sections array.

  UINT32  SectionsIndex = 0;

  // Prepare one SV_SPECIFIC section (HelloSection).
  // For demonstration purposes, use a callback to copy the data.
  // In real code, you would only use a callback if you need to perform custom logic to read/generate the data.
  pSection        = &Sections[SectionsIndex++];
  pSection->Type  = RAW_DUMP_SECTION_SV_SPECIFIC;
  pSection->pName = HelloSectionName;
  CopyGuid ((GUID *)pSection->Information.SVSpecific.SVSpecificData, &HelloSectionGuid);
  pSection->pDataStart       = HelloSectionData;
  pSection->DataSize         = HelloSectionDataSize;
  pSection->DataCopyCallback = CopyHelloDataCallback; // Demonstrate using a callback (normally you would set this to NULL).

  // Prepare the DDR_RANGE sections.
  for (UINT8 const *DescPos = MemoryMap; DescPos < MemoryMap + MemoryMapSize; DescPos += DescriptorSize) {
    EFI_MEMORY_DESCRIPTOR const  *Desc = (EFI_MEMORY_DESCRIPTOR const *)DescPos;
    if (Desc->Type != EfiConventionalMemory) {
      continue;
    }

    pSection                            = &Sections[SectionsIndex++];
    pSection->Type                      = RAW_DUMP_SECTION_DDR_RANGE;
    pSection->Information.DdrRange.Base = Desc->PhysicalStart;
    pSection->pDataStart                = (void const *)(UINTN)Desc->PhysicalStart;
    pSection->DataSize                  = EFI_PAGES_TO_SIZE (Desc->NumberOfPages);
  }

  ASSERT (SectionsCount == SectionsIndex);

  // Fill in the CPU context data for each core.

  CONTEXT_ARM64  CpuContexts[4] = { 0 }; // TODO: Use the actual number of CPUs.
  for (unsigned i = 0; i < ARRAY_SIZE (CpuContexts); i += 1) {
    CONTEXT_ARM64  *pContext = &CpuContexts[i];

    // TODO: Get real CPU context data that was captured at the time of the crash.
    pContext->Pc = 0x1234;
  }

  // Create a protocol instance.

  SAMPLE_DUMP_CONFIGURATION_PROTOCOL  Protocol = {
    .Base.Revision        = OfflineDumpConfigurationProtocolRevision_1_0,
    .Base.Begin           = SampleBegin,
    .Base.ReportProgress  = SampleReportProgress,
    .Base.End             = SampleEnd,
    .pSections            = Sections,
    .SectionCount         = SectionsCount,
    .Architecture         = RAW_DUMP_ARCHITECTURE_ARM64,
    .pCpuContexts         = CpuContexts,
    .CpuContextCount      = ARRAY_SIZE (CpuContexts),
    .CpuContextSize       = sizeof(CpuContexts[0]),
    .pVendor              = "Vend",
    .pPlatform            = "Platform",
    .DumpReasonParameter1 = 0x12345678,
    .DumpReasonParameter2 = 0xA,
    .DumpReasonParameter3 = 0x1234,
    .DumpReasonParameter4 = 0x0,
    .Flags                = RAW_DUMP_HEADER_IS_DDR_CACHE_FLUSHED,
  };

  // TODO: Temporary/transitional.
  //
  // Currently, this is a normal function call.
  // In the future, this will be a call to a separate module as follows:
  //
  // 1. Add the protocol to the EFI handle table.
  // 2. Run the "OfflineDumpCollect.efi" application.
  // 3. Unload the protocol from the EFI handle table.
  Status = OfflineDumpCollect (&Protocol.Base);

Done:

  if (MemoryMap != NULL) {
    FreePool (MemoryMap);
  }

  if (Sections != NULL) {
    FreePool (Sections);
  }

  Print (L"Exit: %r\n", Status);
  return Status;
}
