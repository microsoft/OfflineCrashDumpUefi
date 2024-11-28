#include <Library/OfflineDumpWriter.h>
#include <Library/OfflineDumpPartition.h>

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#ifdef __INTELLISENSE__
#define PcdGetBool(x)  TRUE
#endif

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  static UINT32 const  SectionCount  = 10;
  static CHAR8 const   SectionData[] = "Hello, World!";

  EFI_STATUS  Status;
  EFI_HANDLE  BlockDeviceHandle;

  Status = PcdGetBool (PcdOfflineDumpUsePartition)
           // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
    ? FindOfflineDumpPartitionHandle (&BlockDeviceHandle)
           // For testing on Emulator: Look for a raw block device that is not a partition.
    : FindOfflineDumpRawBlockDeviceHandleForTesting (&BlockDeviceHandle);
  if (EFI_ERROR (Status)) {
    Print (L"Find offline dump device failed (%r)\n", Status);
    goto Done;
  }

  OFFLINE_DUMP_WRITER_OPTIONS  Options = {
    .DisableBlockIo2   = FALSE,
    .ForceUnencrypted  = FALSE,
    .BufferCount       = 0,
    .BufferMemoryLimit = 0,
  };
  OFFLINE_DUMP_WRITER          *DumpWriter;

  Status = OfflineDumpWriterOpen (
                                  BlockDeviceHandle,
                                  // Must not include DUMP_VALID or INSUFFICIENT_STORAGE flags -- they're automatic.
                                  0,
                                  SectionCount,
                                  &Options,
                                  &DumpWriter
                                  );
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterOpen() failed (%r)\n", Status);
    goto Done;
  }

  RAW_DUMP_SECTION_INFORMATION  Information;

  ZeroMem (&Information, sizeof (Information));

  for (UINT32 SectionIndex = 0; SectionIndex != SectionCount; SectionIndex += 1) {
    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Should include DUMP_VALID flag if section is valid.
                                            // Must not include INSUFFICIENT_STORAGE flag -- it's automatic.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            1,
                                            0,
                                            RAW_DUMP_SECTION_SV_SPECIFIC,
                                            &Information,
                                            "SV_SPECIFIC",
                                            NULL,
                                            SectionData,
                                            sizeof (SectionData)
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"DumpWriterWriteSection() failed (%r)\n", Status);
      goto Done;
    }
  }

  EFI_STATUS const  LastError           = OfflineDumpWriterLastWriteError (DumpWriter);
  UINT64 const      MediaPos            = OfflineDumpWriterMediaPosition (DumpWriter);
  UINT64 const      MediaSize           = OfflineDumpWriterMediaSize (DumpWriter);
  BOOLEAN  const    InsufficientStorage = OfflineDumpWriterHasInsufficientStorage (DumpWriter);

  Status = OfflineDumpWriterClose (DumpWriter, TRUE);
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
           (unsigned long long)MediaSize,
           (unsigned long long)MediaPos
           );
  }

  if ((LastError != EFI_SUCCESS) || InsufficientStorage) {
    Status = EFI_ABORTED;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:

  Print (L"Exiting (%r)\n", Status);
  return Status;
}
