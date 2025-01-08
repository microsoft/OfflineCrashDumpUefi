#include <OfflineDumpCollect.h>
#include <OfflineDumpPartition.h>
#include <OfflineDumpWriter.h>
#include <OfflineDumpVariables.h>

#include <Protocol/OfflineDumpConfiguration.h>
#include <Guid/OfflineDumpCpuContext.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

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

static EFI_STATUS
OfflineDumpWrite (
  IN OFFLINE_DUMP_CONFIGURATION_PROTOCOL const   *pConfiguration,
  IN OFFLINE_DUMP_CONFIGURATION_DUMP_INFO const  *pDumpInfo
  )
{
  EFI_STATUS                    Status;
  OFFLINE_DUMP_WRITER           *pDumpWriter = NULL;
  RAW_DUMP_SECTION_INFORMATION  Information;

  // Open the dump writer.
  {
    OFFLINE_DUMP_WRITER_OPTIONS  Options = {
      .DisableBlockIo2   = pDumpInfo->DisableBlockIo2,
      .ForceUnencrypted  = pDumpInfo->ForceUnencrypted,
      .BufferCount       = pDumpInfo->BufferCount,
      .BufferMemoryLimit = pDumpInfo->BufferMemoryLimit,
    };
    Status = OfflineDumpWriterOpen (
                                    pDumpInfo->BlockDevice,
                                    pDumpInfo->Flags,
                                    pDumpInfo->SectionCount + 3, // 3 = SYSTEM_INFORMATION + DUMP_REASON + CPU_CONTEXT.
                                    &Options,
                                    &pDumpWriter
                                    );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "OfflineDumpWriterOpen failed (%r)\n", Status);
      return Status;
    }
  }

  // SYSTEM_INFORMATION

  ZeroMem (&Information, sizeof (Information));
  AsciiStrnCpy (Information.SystemInformation.Vendor, pDumpInfo->pVendor, sizeof (Information.SystemInformation.Vendor));
  AsciiStrnCpy (Information.SystemInformation.Platform, pDumpInfo->pPlatform, sizeof (Information.SystemInformation.Platform));
  Information.SystemInformation.Architecture = pDumpInfo->Architecture;

  Status = OfflineDumpWriterWriteSection (
                                          pDumpWriter,
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
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(SystemInformation) failed (%r)\n", Status);
  }

  // DUMP_REASON

  ZeroMem (&Information, sizeof (Information));
  Information.DumpReason.Parameter1 = pDumpInfo->DumpReasonParameter1;
  Information.DumpReason.Parameter2 = pDumpInfo->DumpReasonParameter2;
  Information.DumpReason.Parameter3 = pDumpInfo->DumpReasonParameter3;
  Information.DumpReason.Parameter4 = pDumpInfo->DumpReasonParameter4;

  Status = OfflineDumpWriterWriteSection (
                                          pDumpWriter,
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
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(DumpReason) failed (%r)\n", Status);
  }

  // CPU_CONTEXT

  ZeroMem (&Information, sizeof (Information));

  switch (pDumpInfo->Architecture) {
    case RAW_DUMP_ARCHITECTURE_ARM64:
      Information.CpuContext.Architecture = PROCESSOR_ARCHITECTURE_ARM64;
      break;
    case RAW_DUMP_ARCHITECTURE_X64:
      Information.CpuContext.Architecture = PROCESSOR_ARCHITECTURE_AMD64;
      break;
  }

  Information.CpuContext.CoreCount   = pDumpInfo->CpuContextCount;
  Information.CpuContext.ContextSize = pDumpInfo->CpuContextSize;

  Status = OfflineDumpWriterWriteSection (
                                          pDumpWriter,
                                          RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                          RAW_DUMP_CPU_CONTEXT_CURRENT_MAJOR_VERSION,
                                          RAW_DUMP_CPU_CONTEXT_CURRENT_MINOR_VERSION,
                                          RAW_DUMP_SECTION_CPU_CONTEXT,
                                          &Information,
                                          "CpuContext",
                                          NULL, // Use CopyMem instead of a callback.
                                          pDumpInfo->pCpuContexts,
                                          pDumpInfo->CpuContextCount * (UINT64)pDumpInfo->CpuContextSize
                                          );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(CpuContext) failed (%r)\n", Status);
  }

  // Other sections

  UINT64  ExpectedBytes = 0;
  for (UINT32 SectionIndex = 0; SectionIndex < pDumpInfo->SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_CONFIGURATION_SECTION_INFO const * const  pSection = &pDumpInfo->pSections[SectionIndex];

    ExpectedBytes += pSection->DataSize;
  }

  UINT64  WrittenBytes = 0;
  for (UINT32 SectionIndex = 0; SectionIndex < pDumpInfo->SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_CONFIGURATION_SECTION_INFO const * const  pSection = &pDumpInfo->pSections[SectionIndex];

    // TODO: Move this into OfflineDumpWriterWriteSection so that it can be called every N bytes,
    // even when the section is large.
    Status = pConfiguration->ReportProgress (
                                             (OFFLINE_DUMP_CONFIGURATION_PROTOCOL *)pConfiguration,
                                             ExpectedBytes,
                                             WrittenBytes
                                             );
    WrittenBytes += pSection->DataSize;
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_WARN, "ReportProgress returned error (%r), stopping collection\n", Status);
      goto Done;
    }

    UINT16       MajorVersion;
    UINT16       MinorVersion;
    CHAR8 const  *pName;
    switch (pSection->Type) {
      case RAW_DUMP_SECTION_DDR_RANGE:
        MajorVersion = RAW_DUMP_DDR_RANGE_CURRENT_MAJOR_VERSION;
        MinorVersion = RAW_DUMP_DDR_RANGE_CURRENT_MINOR_VERSION;
        pName        = pSection->pName && pSection->pName[0] ? pSection->pName : "DDR";
        break;
      case RAW_DUMP_SECTION_SV_SPECIFIC:
        MajorVersion = RAW_DUMP_SV_SPECIFIC_CURRENT_MAJOR_VERSION;
        MinorVersion = RAW_DUMP_SV_SPECIFIC_CURRENT_MINOR_VERSION;
        pName        = pSection->pName && pSection->pName[0] ? pSection->pName : "SV";
        break;
      default:
        DEBUG_PRINT (DEBUG_WARN, "Unsupported section type %u for section %u\n", pSection->Type, SectionIndex);
        continue;
    }

    RAW_DUMP_SECTION_HEADER_FLAGS const  Flags = pSection->ForceInvalid
      ? pSection->Flags
      : pSection->Flags | RAW_DUMP_SECTION_HEADER_DUMP_VALID;
    Status = OfflineDumpWriterWriteSection (
                                            pDumpWriter,
                                            Flags,
                                            MajorVersion,
                                            MinorVersion,
                                            pSection->Type,
                                            &pSection->Information,
                                            pName,
                                            pSection->DataCopyCallback,
                                            pSection->pDataStart,
                                            pSection->DataSize
                                            );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (
                   DEBUG_WARN,
                   "WriteSection(\"%a\" %u) failed (%r)\n",
                   pName,
                   SectionIndex,
                   Status
                   );
    }
  }

  Status = OfflineDumpWriterLastWriteError (pDumpWriter);

Done:

  EFI_STATUS const  CloseStatus = OfflineDumpWriterClose (pDumpWriter, !EFI_ERROR (Status));
  if (!EFI_ERROR (Status)) {
    Status = CloseStatus;
  }

  return Status;
}

EFI_STATUS
OfflineDumpCollect (
  IN OFFLINE_DUMP_CONFIGURATION_PROTOCOL const  *pConfiguration
  )
{
  EFI_STATUS  Status;

  // Validate pConfiguration

  if (pConfiguration->Revision < OfflineDumpConfigurationProtocolRevision_1_0) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "Unsupported protocol revision 0x%X; expected 0x%X or later\n",
                 pConfiguration->Revision,
                 OfflineDumpConfigurationProtocolRevision_1_0
                 );
    return EFI_UNSUPPORTED;
  }

  if ((pConfiguration->Begin == NULL) ||
      (pConfiguration->ReportProgress == NULL) ||
      (pConfiguration->End == NULL))
  {
    DEBUG_PRINT (DEBUG_ERROR, "One or more required protocol pointers is NULL.\n");
    return EFI_UNSUPPORTED;
  }

  // Call Begin to get DumpInfo.

  OFFLINE_DUMP_USE_CAPABILITY_FLAGS  UseCapabilityFlags;
  (void)GetVariableOfflineMemoryDumpUseCapability (&UseCapabilityFlags);

  OFFLINE_DUMP_CONFIGURATION_DUMP_INFO  DumpInfo = { 0 };

  {
    OFFLINE_DUMP_CONFIGURATION_SESSION_INFO  SessionInfo = { 0 };
    SessionInfo.WriterRevision     = OfflineDumpConfigurationProtocolRevisionCurrent;
    SessionInfo.UseCapabilityFlags = UseCapabilityFlags;

    Status = pConfiguration->Begin (
                                    (OFFLINE_DUMP_CONFIGURATION_PROTOCOL *)pConfiguration,
                                    sizeof (SessionInfo),
                                    &SessionInfo,
                                    sizeof (DumpInfo),
                                    &DumpInfo
                                    );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "protocol.Begin failed (%r)\n", Status);
      return Status;
    }
  }

  // Validate DumpInfo

  if (DumpInfo.SectionCount > 0x8000000) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.SectionCount %u is too large\n", DumpInfo.SectionCount);
    Status = EFI_UNSUPPORTED;
    goto Done;
  }

  switch (DumpInfo.Architecture) {
    default:
      DEBUG_PRINT (DEBUG_ERROR, "Unsupported DumpInfo.Architecture %u\n", DumpInfo.Architecture);
      Status = EFI_UNSUPPORTED;
      goto Done;
    case RAW_DUMP_ARCHITECTURE_ARM64:
    case RAW_DUMP_ARCHITECTURE_X64:
      break;
  }

  if (DumpInfo.Flags & (RAW_DUMP_HEADER_DUMP_VALID | RAW_DUMP_HEADER_INSUFFICIENT_STORAGE | RAW_DUMP_HEADER_IS_HYPERV_DATA_PROTECTED)) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Flags 0x%X contains a prohibited flag\n", DumpInfo.Flags);
    Status = EFI_UNSUPPORTED;
    goto Done;
  }

  if (DumpInfo.Reserved) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Reserved is non-NULL\n");
    Status = EFI_UNSUPPORTED;
    goto Done;
  }

  if (DumpInfo.ForceUnencrypted) {
    DEBUG_PRINT (DEBUG_WARN, "Forcing unencrypted dump\n");
  }

  for (UINT32 SectionIndex = 0; SectionIndex < DumpInfo.SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_CONFIGURATION_SECTION_INFO const * const  pSection = &DumpInfo.pSections[SectionIndex];

    if (pSection->Flags & (RAW_DUMP_SECTION_HEADER_DUMP_VALID | RAW_DUMP_SECTION_HEADER_INSUFFICIENT_STORAGE)) {
      DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Sections[%u].Flags 0x%X contains a prohibited flag\n", SectionIndex, pSection->Flags);
      Status = EFI_UNSUPPORTED;
      goto Done;
    }

    if ((pSection->Reserved1 != 0) || (pSection->Reserved2 != 0) || (pSection->Reserved3 != 0) || (pSection->Reserved4 != NULL)) {
      DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Sections[%u].Reserved field is non-zero\n", SectionIndex);
      Status = EFI_UNSUPPORTED;
      goto Done;
    }
  }

  // Determine dump device

  if (DumpInfo.BlockDevice != NULL) {
    // Use the device specified by the protocol.
  } else if (UseCapabilityFlags & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN) {
    // Find the device via GPT scan.
    Status = FindOfflineDumpPartitionHandle (&DumpInfo.BlockDevice);
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "FindOfflineDumpPartitionHandle failed (%r)\n", Status);
      goto Done;
    }
  } else {
    DEBUG_PRINT (DEBUG_ERROR, "Dump disabled: OfflineMemoryDumpUseCapability = 0x%X\n", UseCapabilityFlags);
    Status = EFI_NOT_STARTED;
    goto Done;
  }

  // Write the dump

  Status = OfflineDumpWrite (pConfiguration, &DumpInfo);

Done:

  pConfiguration->End ((OFFLINE_DUMP_CONFIGURATION_PROTOCOL *)pConfiguration, Status);
  return Status;
}
