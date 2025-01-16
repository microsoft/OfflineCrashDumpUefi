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

// Silicon-vendor sections are typically identified by GUID.
// GUID {740A5381-34D6-488d-B03C-A8E6D0181808} identifies the demonstration "Hello" section.
static GUID const  HelloSectionGuid =
{
  0x740a5381, 0x34d6, 0x488d, {
    0xb0,     0x3c,   0xa8,   0xe6, 0xd0, 0x18, 0x18, 0x8
  }
};

// Normally, section data is provided as a pointer to a buffer, but it can also be generated
// by a callback. This is a simple example of a callback that generates a section's data.
static BOOLEAN EFIAPI
CopyHelloDataCallback (
  IN void const  *pDataStart,
  IN UINTN       Offset,
  IN UINTN       Size,
  OUT UINT8      *pDestinationPos
  )
{
  // Callback should perform any custom logic needed to generate the section's data,
  // e.g. it could call into a coprocessor to copy the data.
  //
  // In real code, you should not use a callback if you are just performing a normal CopyMem.
  // If you pass NULL as the callback, the collector will perform an optimized copy as if by CopyMem.
  CopyMem (pDestinationPos, (UINT8 *)pDataStart + Offset, Size);
  return TRUE;
}

// This is the data we need for our implementation of OFFLINE_DUMP_PROVIDER_PROTOCOL.
// We pass this protocol implementation to the collector.
typedef struct {
  // Protocol implementation must always start with the protocol interface:

  OFFLINE_DUMP_PROVIDER_PROTOCOL    Protocol;

  // Additional fields needed by the protocol implementation can go here:

  OFFLINE_DUMP_INFO                 DumpInfo;  // Information that will be returned by Begin.
  EFI_STATUS                        EndStatus; // Status that will be captured by End.
} SAMPLE_DUMP_PROVIDER;

// Simple implementation of the Begin callback for the OfflineDumpProviderProtocol.
// This is called by the collector to get dump configuration and dump data.
// It needs to fill in the pDumpInfo information.
static EFI_STATUS
SampleBegin (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL     *pThisProtocol,
  IN  UINTN                              CollectorInfoSize,
  IN  OFFLINE_DUMP_COLLECTOR_INFO const  *pCollectorInfo,
  IN  UINTN                              DumpInfoSize,
  OUT OFFLINE_DUMP_INFO                  *pDumpInfo
  )
{
  EFI_STATUS                   Status;
  SAMPLE_DUMP_PROVIDER *const  pThis = BASE_CR (pThisProtocol, SAMPLE_DUMP_PROVIDER, Protocol);

  // CollectorInfo holds the information we copy from pCollectorInfo.
  OFFLINE_DUMP_COLLECTOR_INFO  CollectorInfo = { 0 };

  // Copy the collector's CollectorInfo buffer to our local CollectorInfo.
  // In case of size mismatch between us and the collector, copy the smaller of the two.
  CopyMem (&CollectorInfo, pCollectorInfo, MIN (CollectorInfoSize, sizeof (CollectorInfo)));

  // Begin performs any work needed to prepare for the dump. In this case, most of the work
  // happened during protocol initialization.
  //
  // We want to validate UseCapabilityFlags before searching for the BlockDevice,
  // so let's do that now.

  if (0 == (CollectorInfo.UseCapabilityFlags & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN)) {
    Print (L"Dump disabled: OfflineMemoryDumpUseCapability = 0x%X.\n", CollectorInfo.UseCapabilityFlags);
    Status = EFI_NOT_STARTED;
    goto Done;
  }

  // Fill in the BlockDevice value in the protocol's DumpInfo:
  Status = PcdGetBool (PcdOfflineDumpUsePartition)
           // For normal dumps: Look for a GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
           ? FindOfflineDumpPartitionHandle (&pThis->DumpInfo.BlockDevice)
           // For testing on X86 Emulator: Look for a raw block device that is not a partition.
           : FindOfflineDumpRawBlockDeviceHandleForTesting (&pThis->DumpInfo.BlockDevice);
  if (EFI_ERROR (Status)) {
    Print (L"Dump error: FindOfflineDumpPartitionHandle failed (%r)\n", Status);
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:

  // Copy our DumpInfo to the collector's DumpInfo buffer.
  // In case of size mismatch between us and the collector, copy the smaller of the two.
  CopyMem (pDumpInfo, &pThis->DumpInfo, MIN (DumpInfoSize, sizeof (pThis->DumpInfo)));

  Print (L"Begin: %r\n", Status);
  return Status;
}

// Simple implementation of the End callback for the OfflineDumpProviderProtocol.
// This is called by the collector to signal that dump collection has ended.
// It should perform cleanup as needed.
// This will be called if and only if the Begin callback returned successfully.
static VOID
SampleEnd (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pThisProtocol,
  IN  EFI_STATUS                      Status
  )
{
  SAMPLE_DUMP_PROVIDER *const  pThis = BASE_CR (pThisProtocol, SAMPLE_DUMP_PROVIDER, Protocol);

  pThis->DumpInfo.BlockDevice = NULL; // Cleanup as needed.
  Print (L"End: %r\n", Status);       // OfflineDumpWrite will return the same status.
}

// Simple implementation of the ReportProgress callback for the OfflineDumpProviderProtocol.
// This is called periodically by the collector to give the provider a chance to update progress UI.
// This will only be called if the Begin callback returned successfully.
static EFI_STATUS
SampleReportProgress (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pThisProtocol,
  IN  UINT64                          ExpectedBytes,
  IN  UINT64                          WrittenBytes
  )
{
  (void)pThisProtocol; // Parameter not used.

  // This implementation just prints the progress.
  // A more complex implementation might update a progress bar or other UI.
  Print (L"ReportProgress: %llu/%llu\n", (llu_t)WrittenBytes, (llu_t)ExpectedBytes);
  return EFI_SUCCESS; // If this returns an error, the collector will stop writing the dump.
}

EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS            Status;
  UINT8                 *MemoryMap = NULL;
  OFFLINE_DUMP_SECTION  *Sections  = NULL;
  OFFLINE_DUMP_SECTION  *pSection  = NULL;

  UINTN   MemoryMapSize = 0;
  UINTN   MapKey;
  UINTN   DescriptorSize;
  UINT32  DescriptorVersion;

  // Get the memory map.
  // TODO: Real crash dump will probably use a customized memory map to include carve-outs.

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

  Sections = AllocateZeroPool (SectionsCount * sizeof (OFFLINE_DUMP_SECTION));
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
  pSection->Type  = OfflineDumpSectionTypeSvSpecific;
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
    pSection->Type                      = OfflineDumpSectionTypeDdrRange;
    pSection->Information.DdrRange.Base = Desc->PhysicalStart;
    pSection->pDataStart                = (void const *)(UINTN)Desc->PhysicalStart;
    pSection->DataSize                  = EFI_PAGES_TO_SIZE (Desc->NumberOfPages);
  }

  ASSERT (SectionsCount == SectionsIndex);

  // Fill in the CPU context data for each core.

  #define CPU_CONTEXT_COUNT  4 // TODO: Get the actual number of CPU cores.
  CONTEXT_ARM64  CpuContexts[CPU_CONTEXT_COUNT] = { 0 };
  UINT32 const   CpuContextCount                = CPU_CONTEXT_COUNT;
  for (unsigned i = 0; i < CpuContextCount; i += 1) {
    CONTEXT_ARM64  *pContext = &CpuContexts[i];

    // TODO: Get real CPU context data that was captured at the time of the crash.
    pContext->Pc = 0x1234;
  }

  // Create our provider.

  SAMPLE_DUMP_PROVIDER  SampleDumpProvider = {
    // Provider public fields (used by the collector):
    .Protocol.Revision       = OfflineDumpProviderProtocolRevision_1_0,
    .Protocol.Begin          = SampleBegin,
    .Protocol.ReportProgress = SampleReportProgress,
    .Protocol.End            = SampleEnd,

    // Provider private fields (used by the callbacks):
    .DumpInfo.BlockDevice          = NULL,       // Filled in by SampleBegin.
    .DumpInfo.pSections            = Sections,
    .DumpInfo.SectionCount         = SectionsCount,
    .DumpInfo.Architecture         = RAW_DUMP_ARCHITECTURE_ARM64,
    .DumpInfo.pCpuContexts         = CpuContexts,
    .DumpInfo.CpuContextCount      = CpuContextCount,
    .DumpInfo.CpuContextSize       = sizeof (CpuContexts[0]),
    .DumpInfo.pVendor              = "Vend",     // TODO: Use real vendor.
    .DumpInfo.pPlatform            = "Platform", // TODO: Use real platform.
    .DumpInfo.DumpReasonParameter1 = 0x12345678, // TODO: Use real dump bucket parameters.
    .DumpInfo.DumpReasonParameter2 = 0xA,
    .DumpInfo.DumpReasonParameter3 = 0x1234,
    .DumpInfo.DumpReasonParameter4 = 0x0,
    .DumpInfo.Flags                = RAW_DUMP_HEADER_IS_DDR_CACHE_FLUSHED,
  };

  // Collect the dump.

  // Note: Currently, this is a normal function call.
  // In the future, this will be a call to a separate module as follows:
  // 1. Add the protocol to the EFI handle table.
  // 2. Run the "OfflineDumpCollect.efi" application.
  // 3. Unload the protocol from the EFI handle table.
  Status = OfflineDumpCollect (&SampleDumpProvider.Protocol);

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
