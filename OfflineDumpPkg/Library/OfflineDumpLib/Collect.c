#include <OfflineDumpLib.h>
#include <Library/OfflineDumpWriter.h>
#include <Library/OfflineDumpVariables.h>

#include <Protocol/OfflineDumpProvider.h>
#include <Guid/OfflineDumpCpuContext.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>

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

// Returns NULL if the section is ok, else a string describing the reason it is skipped.
static CHAR8 const *
OfflineDumpSectionSkipReason (
  IN OFFLINE_DUMP_SECTION const  *pSection
  )
{
  switch (pSection->Type) {
    case OfflineDumpSectionTypeDdrRange:
    case OfflineDumpSectionTypeSvSpecific:
      break;
    default:
      return "unsupported Type";
  }

  if ((pSection->Options.Reserved1 != 0) ||
      (pSection->Options.Reserved2 != 0) ||
      (pSection->Reserved1 != NULL))
  {
    return "non-zero Reserved field";
  }

  if (pSection->Flags & (RAW_DUMP_SECTION_HEADER_DUMP_VALID | RAW_DUMP_SECTION_HEADER_INSUFFICIENT_STORAGE)) {
    return "prohibited flag in Flags";
  }

  return NULL;
}

static CHAR8 const *
MakeSectionName (
  CHAR8 const  *pProvidedName,
  CHAR8 const  *pDefaultPrefix,
  UINT32       Index,
  CHAR8        NameBuffer[],
  UINTN        NameBufferSize
  )
{
  if (pProvidedName && pProvidedName[0]) {
    return pProvidedName;
  } else {
    AsciiSPrint (NameBuffer, NameBufferSize, "%a-%03u.bin", pDefaultPrefix, Index);
    return NameBuffer;
  }
}

static OFFLINE_DUMP_END_INFO
OfflineDumpWrite (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL const  *pProvider,
  IN OFFLINE_DUMP_INFO const               *pDumpInfo
  )
{
  OFFLINE_DUMP_END_INFO         EndInfo      = { 0 };
  OFFLINE_DUMP_WRITER           *pDumpWriter = NULL;
  RAW_DUMP_SECTION_INFORMATION  Information;

  // Count the sections and bytes to write.

  UINT32                      FinalSectionCount = 0;
  OFFLINE_DUMP_PROGRESS_INFO  ProgressInfo      = { 0 }; // Only for progress reporting. Doesn't include small sections.

  for (UINT32 SectionIndex = 0; SectionIndex < pDumpInfo->SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_SECTION const * const  pSection = &pDumpInfo->pSections[SectionIndex];
    if (NULL != OfflineDumpSectionSkipReason (pSection)) {
      continue;
    }

    FinalSectionCount          += 1;
    ProgressInfo.ExpectedBytes += pSection->DataSize;
  }

  FinalSectionCount += 3; // Account for SYSTEM_INFORMATION, DUMP_REASON, CPU_CONTEXT.

  // Open the dump writer.
  {
    OFFLINE_DUMP_WRITER_OPTIONS  Options = {
      .DisableBlockIo2   = (BOOLEAN)pDumpInfo->Options.DisableBlockIo2,
      .ForceUnencrypted  = (BOOLEAN)pDumpInfo->Options.ForceUnencrypted,
      .BufferCount       = (UINT8)pDumpInfo->Options.BufferCount,
      .BufferMemoryLimit = pDumpInfo->Options.BufferMemoryLimit,
    };
    EndInfo.Status = OfflineDumpWriterOpen (
                                            pDumpInfo->BlockDevice,
                                            pDumpInfo->Flags,
                                            FinalSectionCount,
                                            &Options,
                                            &pDumpWriter
                                            );
    if (EFI_ERROR (EndInfo.Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "OfflineDumpWriterOpen failed (%r)\n", EndInfo.Status);
      return EndInfo;
    }
  }

  EndInfo.EncryptionAlgorithm = OfflineDumpWriterEncryptionAlgorithm (pDumpWriter);
  EndInfo.SizeAvailable       = OfflineDumpWriterMediaSize (pDumpWriter);

  // SYSTEM_INFORMATION

  ZeroMem (&Information, sizeof (Information));
  AsciiStrnCpy (Information.SystemInformation.Vendor, pDumpInfo->pVendor, sizeof (Information.SystemInformation.Vendor));
  AsciiStrnCpy (Information.SystemInformation.Platform, pDumpInfo->pPlatform, sizeof (Information.SystemInformation.Platform));
  Information.SystemInformation.Architecture = pDumpInfo->Architecture;

  EndInfo.Status = OfflineDumpWriterWriteSection (
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
  if (EFI_ERROR (EndInfo.Status)) {
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(SystemInformation) failed (%r)\n", EndInfo.Status);
  }

  // DUMP_REASON

  ZeroMem (&Information, sizeof (Information));
  Information.DumpReason.Parameter1 = pDumpInfo->DumpReasonParameter1;
  Information.DumpReason.Parameter2 = pDumpInfo->DumpReasonParameter2;
  Information.DumpReason.Parameter3 = pDumpInfo->DumpReasonParameter3;
  Information.DumpReason.Parameter4 = pDumpInfo->DumpReasonParameter4;

  EndInfo.Status = OfflineDumpWriterWriteSection (
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
  if (EFI_ERROR (EndInfo.Status)) {
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(DumpReason) failed (%r)\n", EndInfo.Status);
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

  EndInfo.Status = OfflineDumpWriterWriteSection (
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
  if (EFI_ERROR (EndInfo.Status)) {
    DEBUG_PRINT (DEBUG_WARN, "WriteSection(CpuContext) failed (%r)\n", EndInfo.Status);
  }

  // Other sections

  for (UINT32 SectionIndex = 0; SectionIndex < pDumpInfo->SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_SECTION const * const  pSection = &pDumpInfo->pSections[SectionIndex];
    if (NULL != OfflineDumpSectionSkipReason (pSection)) {
      continue;
    }

    // TODO: Move this into OfflineDumpWriterWriteSection so that it can be called every N bytes,
    // even when the section is large.
    EndInfo.Status = pProvider->ReportProgress (
                                                (OFFLINE_DUMP_PROVIDER_PROTOCOL *)pProvider,
                                                sizeof (ProgressInfo),
                                                &ProgressInfo
                                                );
    ProgressInfo.WrittenBytes += pSection->DataSize;
    if (EFI_ERROR (EndInfo.Status)) {
      DEBUG_PRINT (DEBUG_WARN, "ReportProgress returned error (%r), stopping collection\n", EndInfo.Status);
      goto Done;
    }

    UINT16                 MajorVersion;
    UINT16                 MinorVersion;
    RAW_DUMP_SECTION_TYPE  Type;
    CHAR8 const            *pName;
    CHAR8                  NameBuffer[21];
    switch (pSection->Type) {
      case OfflineDumpSectionTypeDdrRange:
        MajorVersion = RAW_DUMP_DDR_RANGE_CURRENT_MAJOR_VERSION;
        MinorVersion = RAW_DUMP_DDR_RANGE_CURRENT_MINOR_VERSION;
        Type         = RAW_DUMP_SECTION_DDR_RANGE;
        pName        = MakeSectionName (pSection->pName, "DDR", SectionIndex, NameBuffer, sizeof (NameBuffer));
        break;

      case OfflineDumpSectionTypeSvSpecific:
        MajorVersion = RAW_DUMP_SV_SPECIFIC_CURRENT_MAJOR_VERSION;
        MinorVersion = RAW_DUMP_SV_SPECIFIC_CURRENT_MINOR_VERSION;
        Type         = RAW_DUMP_SECTION_SV_SPECIFIC;
        pName        = MakeSectionName (pSection->pName, "SV", SectionIndex, NameBuffer, sizeof (NameBuffer));
        break;

      default:
        // This should never happen because we already checked for unsupported types.
        ASSERT (FALSE);
        continue;
    }

    RAW_DUMP_SECTION_HEADER_FLAGS const  Flags = pSection->Options.ForceSectionInvalid
      ? pSection->Flags
      : pSection->Flags | RAW_DUMP_SECTION_HEADER_DUMP_VALID;
    EndInfo.Status = OfflineDumpWriterWriteSection (
                                                    pDumpWriter,
                                                    Flags,
                                                    MajorVersion,
                                                    MinorVersion,
                                                    Type,
                                                    &pSection->Information,
                                                    pName,
                                                    pSection->DataCopyCallback,
                                                    pSection->pDataStart,
                                                    pSection->DataSize
                                                    );
    if (EFI_ERROR (EndInfo.Status)) {
      DEBUG_PRINT (
                   DEBUG_WARN,
                   "WriteSection(\"%a\" %u) failed (%r)\n",
                   pName,
                   SectionIndex,
                   EndInfo.Status
                   );
    }
  }

  EndInfo.Status       = OfflineDumpWriterLastWriteError (pDumpWriter);
  EndInfo.SizeRequired = OfflineDumpWriterMediaPosition (pDumpWriter);

Done:

  EFI_STATUS const  CloseStatus = OfflineDumpWriterClose (pDumpWriter, !EFI_ERROR (EndInfo.Status));
  if (!EFI_ERROR (EndInfo.Status)) {
    EndInfo.Status = CloseStatus;
  }

  return EndInfo;
}

EFI_STATUS
OfflineDumpCollect (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL const  *pProvider
  )
{
  OFFLINE_DUMP_END_INFO  EndInfo = { 0 };

  // Validate pProvider

  if (pProvider->Revision < OfflineDumpProviderProtocolRevision_1_0) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "Unsupported protocol revision 0x%X; expected 0x%X or later\n",
                 pProvider->Revision,
                 OfflineDumpProviderProtocolRevision_1_0
                 );
    return EFI_UNSUPPORTED;
  }

  if ((pProvider->Begin == NULL) ||
      (pProvider->ReportProgress == NULL) ||
      (pProvider->End == NULL))
  {
    DEBUG_PRINT (DEBUG_ERROR, "One or more required protocol pointers is NULL.\n");
    return EFI_UNSUPPORTED;
  }

  // Call Begin to get DumpInfo.

  OFFLINE_DUMP_USE_CAPABILITY_FLAGS  UseCapabilityFlags;
  (void)GetVariableOfflineMemoryDumpUseCapability (&UseCapabilityFlags);

  OFFLINE_DUMP_INFO  DumpInfo = { 0 };

  {
    OFFLINE_DUMP_BEGIN_INFO  BeginInfo = { 0 };
    BeginInfo.CollectorRevision  = OfflineDumpProviderProtocolRevisionCurrent;
    BeginInfo.UseCapabilityFlags = UseCapabilityFlags;

    EndInfo.Status = pProvider->Begin (
                                       (OFFLINE_DUMP_PROVIDER_PROTOCOL *)pProvider,
                                       sizeof (BeginInfo),
                                       &BeginInfo,
                                       sizeof (DumpInfo),
                                       &DumpInfo
                                       );
    if (EFI_ERROR (EndInfo.Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "protocol.Begin failed (%r)\n", EndInfo.Status);
      return EndInfo.Status;
    }
  }

  // Validate DumpInfo

  if (DumpInfo.SectionCount > 0x80000000) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.SectionCount %u is too large\n", DumpInfo.SectionCount);
    EndInfo.Status = EFI_UNSUPPORTED;
    goto Done;
  }

  switch (DumpInfo.Architecture) {
    default:
      DEBUG_PRINT (DEBUG_ERROR, "Unsupported DumpInfo.Architecture %u\n", DumpInfo.Architecture);
      EndInfo.Status = EFI_UNSUPPORTED;
      goto Done;
    case RAW_DUMP_ARCHITECTURE_ARM64:
    case RAW_DUMP_ARCHITECTURE_X64:
      break;
  }

  if (DumpInfo.Flags & (RAW_DUMP_HEADER_DUMP_VALID | RAW_DUMP_HEADER_INSUFFICIENT_STORAGE | RAW_DUMP_HEADER_IS_HYPERV_DATA_PROTECTED)) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Flags 0x%X contains a prohibited flag\n", DumpInfo.Flags);
    EndInfo.Status = EFI_UNSUPPORTED;
    goto Done;
  }

  if (DumpInfo.Options.Reserved1 != 0) {
    // Not fatal.
    DEBUG_PRINT (DEBUG_WARN, "DumpInfo.Options.Reserved1 is non-zero\n");
  }

  if (DumpInfo.Reserved1) {
    DEBUG_PRINT (DEBUG_ERROR, "DumpInfo.Reserved1 is non-zero\n");
    EndInfo.Status = EFI_UNSUPPORTED;
    goto Done;
  }

  if (DumpInfo.Options.ForceUnencrypted) {
    DEBUG_PRINT (DEBUG_WARN, "Forcing unencrypted dump\n");
  }

  if (DumpInfo.Options.ForceUnredacted) {
    DEBUG_PRINT (DEBUG_WARN, "Forcing unredacted dump\n");
  }

  for (UINT32 SectionIndex = 0; SectionIndex < DumpInfo.SectionCount; SectionIndex += 1) {
    OFFLINE_DUMP_SECTION const * const  pSection = &DumpInfo.pSections[SectionIndex];

    CHAR8 const  *pSkipReason = OfflineDumpSectionSkipReason (pSection);
    if (pSkipReason != NULL) {
      DEBUG_PRINT (DEBUG_WARN, "DumpInfo.Sections[%u] skipped: %a\n", SectionIndex, pSkipReason);
    }
  }

  // Determine dump device

  if (DumpInfo.BlockDevice != NULL) {
    // Use the device specified by the protocol.
  } else if (UseCapabilityFlags & OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN) {
    // Find the device via GPT scan.
    EndInfo.Status = FindOfflineDumpPartitionHandle (&DumpInfo.BlockDevice);
    if (EFI_ERROR (EndInfo.Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "FindOfflineDumpPartitionHandle failed (%r)\n", EndInfo.Status);
      goto Done;
    }
  } else {
    DEBUG_PRINT (DEBUG_ERROR, "Dump disabled: OfflineMemoryDumpUseCapability = 0x%X\n", UseCapabilityFlags);
    EndInfo.Status = EFI_NOT_STARTED;
    goto Done;
  }

  // Set up redaction.

  switch (DumpInfo.SecureKernelState) {
    case OfflineDumpSecureKernelStateNotStarted:

      // Redaction not needed.
      break;

    case OfflineDumpSecureKernelStateStarted:

      if (DumpInfo.Options.ForceUnredacted) {
        // Redaction not needed.
        break;
      }

      // Redaction needed. Configuration data required.
      if ((DumpInfo.pSecureOfflineDumpConfiguration == NULL) || (DumpInfo.SecureOfflineDumpConfigurationSize == 0)) {
        DEBUG_PRINT (DEBUG_ERROR, "Secure kernel started but SecureOfflineDumpConfiguration not present. Dump cannot be collected.\n");
        EndInfo.Status = EFI_INVALID_PARAMETER;
        goto Done;
      }

      DEBUG_PRINT (DEBUG_ERROR, "SecureOfflineDumpConfiguration parsing not yet implemented. Dump cannot be collected.\n");
      EndInfo.Status = EFI_UNSUPPORTED;
      goto Done;

    default:

      DEBUG_PRINT (DEBUG_ERROR, "Unrecognized DumpInfo.SecureKernelState value %u\n", DumpInfo.SecureKernelState);
      EndInfo.Status = EFI_INVALID_PARAMETER;
      goto Done;
  }

  // Write the dump

  EndInfo = OfflineDumpWrite (pProvider, &DumpInfo);

Done:

  pProvider->End ((OFFLINE_DUMP_PROVIDER_PROTOCOL *)pProvider, sizeof (EndInfo), &EndInfo);
  return EndInfo.Status;
}
