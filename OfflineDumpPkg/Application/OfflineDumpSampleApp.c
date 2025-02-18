#include <Library/OfflineDumpLib.h>
#include <Guid/OfflineDumpCpuContext.h> // CONTEXT_AMD64, CONTEXT_ARM64

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h> // ASSERT
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/TimerLib.h> // For benchmarking.
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>

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
  // If you pass NULL as the callback, the writer will perform an optimized copy as if by CopyMem.
  CopyMem (pDestinationPos, (UINT8 *)pDataStart + Offset, Size);
  return TRUE;
}

// This is the data we need for our implementation of OFFLINE_DUMP_PROVIDER_PROTOCOL.
// We pass this protocol implementation to the writer.
typedef struct {
  // Protocol implementation must always start with the protocol interface:

  OFFLINE_DUMP_PROVIDER_PROTOCOL    Protocol;

  // Additional fields needed by the protocol implementation can go here:

  OFFLINE_DUMP_INFO                 DumpInfo;  // Information that will be returned by Begin.
  OFFLINE_DUMP_END_INFO             EndInfo;   // Information that was captured by End.
} SAMPLE_DUMP_PROVIDER;

// Simple implementation of the Begin callback for the OfflineDumpProviderProtocol.
// This is called by the writer to get dump configuration and dump data.
// It needs to fill in the pDumpInfo information.
static EFI_STATUS
SampleBegin (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pThisProtocol,
  IN  UINTN                           BeginInfoSize,
  IN  OFFLINE_DUMP_BEGIN_INFO const   *pBeginInfo,
  IN  UINTN                           DumpInfoSize,
  OUT OFFLINE_DUMP_INFO               *pDumpInfo
  )
{
  EFI_STATUS                   Status;
  SAMPLE_DUMP_PROVIDER *const  pThis = BASE_CR (pThisProtocol, SAMPLE_DUMP_PROVIDER, Protocol);

  // BeginInfo holds the information we copy from pBeginInfo.
  OFFLINE_DUMP_BEGIN_INFO  BeginInfo = { 0 };

  // Copy the writer's BeginInfo buffer to our local BeginInfo.
  // In case of size mismatch between us and the writer, copy the smaller of the two.
  CopyMem (&BeginInfo, pBeginInfo, MIN (BeginInfoSize, sizeof (BeginInfo)));

  // Begin performs any work needed to prepare for the dump. In this case, most of the work
  // happened during protocol initialization.
  //
  // We want to validate UseCapabilityFlags before searching for the BlockDevice,
  // so let's do that now.

  if (0 == (BeginInfo.UseCapabilityFlags & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN)) {
    Print (L"Dump disabled: OfflineMemoryDumpUseCapability = 0x%X.\n", BeginInfo.UseCapabilityFlags);
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

  // Copy our DumpInfo to the writer's DumpInfo buffer.
  // In case of size mismatch between us and the writer, copy the smaller of the two.
  CopyMem (pDumpInfo, &pThis->DumpInfo, MIN (DumpInfoSize, sizeof (pThis->DumpInfo)));

  Print (L"Begin: %r\n", Status);
  return Status;
}

// Simple implementation of the End callback for the OfflineDumpProviderProtocol.
// This is called by the writer to signal that dump generation has ended.
// It should perform cleanup as needed.
// This will be called if and only if the Begin callback returned successfully.
static VOID
SampleEnd (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pThisProtocol,
  IN  UINTN                           EndInfoSize,
  IN  OFFLINE_DUMP_END_INFO const     *pEndInfo
  )
{
  SAMPLE_DUMP_PROVIDER *const  pThis = BASE_CR (pThisProtocol, SAMPLE_DUMP_PROVIDER, Protocol);

  // Copy the writer's EndInfo buffer to our local EndInfo.
  // In case of size mismatch between us and the writer, copy the smaller of the two.
  CopyMem (&pThis->EndInfo, pEndInfo, MIN (EndInfoSize, sizeof (pThis->EndInfo)));

  pThis->DumpInfo.BlockDevice = NULL;          // Cleanup as needed.
  Print (
         L"End: ENC=%u Status=%r\n",
         (unsigned)pThis->EndInfo.EncryptionAlgorithm,
         pThis->EndInfo.Status // OfflineDumpWrite will return the same status.
         );
}

// Simple implementation of the ReportProgress callback for the OfflineDumpProviderProtocol.
// This is called periodically by the writer to give the provider a chance to update progress UI.
// This will only be called if the Begin callback returned successfully.
static EFI_STATUS
SampleReportProgress (
  IN  OFFLINE_DUMP_PROVIDER_PROTOCOL    *pThisProtocol,
  IN  UINTN                             ProgressInfoSize,
  IN  OFFLINE_DUMP_PROGRESS_INFO const  *pProgressInfo
  )
{
  (void)pThisProtocol; // Parameter not used.

  // ProgressInfo holds the information we copy from pProgressInfo.
  OFFLINE_DUMP_PROGRESS_INFO  ProgressInfo = { 0 };

  // Copy the writer's ProgressInfo buffer to our local ProgressInfo.
  // In case of size mismatch between us and the writer, copy the smaller of the two.
  CopyMem (&ProgressInfo, pProgressInfo, MIN (ProgressInfoSize, sizeof (ProgressInfo)));

  // This implementation just prints the progress.
  // A more complex implementation might update a progress bar or other UI.
  Print (L"ReportProgress: %llu/%llu\n", (llu_t)ProgressInfo.WrittenBytes, (llu_t)ProgressInfo.ExpectedBytes);
  return EFI_SUCCESS; // If this returns an error, the writer will stop writing the dump.
}

// Create a device path that points to OfflineDumpWriter.efi.
// For demonstration purposes, look for OfflineDumpWrite.efi in the same directory as
// this sample app.
static EFI_DEVICE_PATH_PROTOCOL *
SampleGetPathToOfflineDumpWrite (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  // Get device path of the running app (OfflineDumpSampleApp.efi).
  EFI_DEVICE_PATH_PROTOCOL  *pThisImagePath = NULL;

  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageDevicePathProtocolGuid, (void **)&pThisImagePath);

  if (EFI_ERROR (Status)) {
    Print (L"HandleProtocol(LoadedImageDevicePath) failed (%r)\n", Status);
    return NULL;
  }

  // Get text path of the running app.
  CHAR16  *pThisImagePathText = ConvertDevicePathToText (pThisImagePath, FALSE, FALSE);
  if (pThisImagePathText == NULL) {
    Print (L"ConvertDevicePathToText(LoadedImageDevicePath) failed\n");
    return NULL;
  }

  // Find the end of the directory part of the running app's path.
  UINTN  ThisImageDirEnd = StrLen (pThisImagePathText);
  while (ThisImageDirEnd > 0 && pThisImagePathText[ThisImageDirEnd - 1] != L'\\') {
    ThisImageDirEnd -= 1;
  }

  // Create a text path that points to OfflineDumpWrite.efi in the running app's directory.
  CHAR16  *pOfflineDumpWritePathText = CatSPrint (NULL, L"%.*sOfflineDumpWrite.efi", (UINT32)ThisImageDirEnd, pThisImagePathText);
  FreePool (pThisImagePathText);
  pThisImagePathText = NULL;
  if (pOfflineDumpWritePathText == NULL) {
    Print (L"CatSPrint(OfflineDumpWritePath) failed\n");
    return NULL;
  }

  Print (L"Running \"%s\"\n", pOfflineDumpWritePathText);

  // Get device path of OfflineDumpWrite.efi in the running app's directory.
  EFI_DEVICE_PATH_PROTOCOL  *pOfflineDumpWritePath = ConvertTextToDevicePath (pOfflineDumpWritePathText);
  FreePool (pOfflineDumpWritePathText);
  pOfflineDumpWritePathText = NULL;
  if (pOfflineDumpWritePath == NULL) {
    Print (L"ConvertTextToDevicePath(OfflineDumpWritePath) failed\n");
    return NULL;
  }

  return pOfflineDumpWritePath;
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
  CONTEXT_ARM64  CpuContexts[CPU_CONTEXT_COUNT];
  SetMem (CpuContexts, sizeof (CpuContexts), 0);
  UINT32 const  CpuContextCount = CPU_CONTEXT_COUNT;
  for (unsigned i = 0; i < CpuContextCount; i += 1) {
    CONTEXT_ARM64  *pContext = &CpuContexts[i];

    // TODO: Get real CPU context data that was captured at the time of the crash.
    pContext->Pc = 0x1234;
  }

  // Create our provider.

  SAMPLE_DUMP_PROVIDER  SampleDumpProvider = {
    // Provider public fields (used by the writer):
    .Protocol.Revision       = OfflineDumpProviderProtocolRevision_1_0,
    .Protocol.Begin          = SampleBegin,
    .Protocol.ReportProgress = SampleReportProgress,
    .Protocol.End            = SampleEnd,

    // Provider private fields (used by the callbacks):
    .DumpInfo                             = {
      .BlockDevice          = NULL, // Filled in by SampleBegin.
      .pSections            = Sections,
      .SectionCount         = SectionsCount,
      .Architecture         = RAW_DUMP_ARCHITECTURE_ARM64,
      .pCpuContexts         = CpuContexts,
      .CpuContextCount      = CpuContextCount,
      .CpuContextSize       = sizeof (CpuContexts[0]),
      .pVendor              = "Vend",     // TODO: Use real vendor.
      .pPlatform            = "Platform", // TODO: Use real platform.
      .DumpReasonParameters =             // TODO: Use real dump bucket parameters.
      {
        0x12345678,
        0xA,
        0x1234,
        0x0,
      },
      .Flags                              = RAW_DUMP_HEADER_IS_DDR_CACHE_FLUSHED, // TODO: Set this only if DDR was flushed before warm boot.
      .pSecureOfflineDumpConfiguration    = NULL,                                 // TODO: Use real configuration ptr from trusted firmware (SMC).
      .SecureOfflineDumpConfigurationSize = 0,                                    // TODO: Use real configuration size from trusted firmware (SMC).
      .SecureOfflineDumpControl           = OfflineDumpControlDumpAllowed,        // TODO: Use real control value from trusted firmware (SMC).
    },
  };

  // Run OfflineDumpWrite.efi to write the dump.
  // Alternative would be to link against OfflineDumpWriterLib and call OfflineDumpWrite(&Protocol).

  EFI_DEVICE_PATH_PROTOCOL  *pOfflineDumpWritePath = SampleGetPathToOfflineDumpWrite (ImageHandle);
  if (pOfflineDumpWritePath == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  UINT64 const  TimeStart = GetPerformanceCounter ();
  Status = OfflineDumpWriteExecutePath (
                                        &SampleDumpProvider.Protocol,
                                        ImageHandle,
                                        pOfflineDumpWritePath
                                        );
  UINT64 const  TimeEnd = GetPerformanceCounter ();
  FreePool (pOfflineDumpWritePath);
  pOfflineDumpWritePath = NULL;

  // Report results.

  if (EFI_ERROR (Status)) {
    Print (
           L"OfflineDumpWrite failed: %r\n",
           Status
           );
  } else if (SampleDumpProvider.EndInfo.SizeRequired > SampleDumpProvider.EndInfo.SizeAvailable) {
    Print (
           L"OfflineDumpWrite truncated: %lluKB required, %lluKB available\n",
           (llu_t)SampleDumpProvider.EndInfo.SizeRequired / 1024,
           (llu_t)SampleDumpProvider.EndInfo.SizeAvailable / 1024
           );
  } else {
    UINT64 const  TimeNS             = GetTimeInNanoSecond (TimeEnd - TimeStart);
    UINT64 const  KilobytesPerSecond = SampleDumpProvider.EndInfo.SizeRequired * (1000000000 / 1024) / (TimeNS ? TimeNS : 1);
    Print (
           L"OfflineDumpWrite succeeded: %lluKB / %llus = %llu KB/s\n",
           (llu_t)SampleDumpProvider.EndInfo.SizeRequired / 1024,
           (llu_t)TimeNS / 1000000000,
           (llu_t)KilobytesPerSecond
           );
  }

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
