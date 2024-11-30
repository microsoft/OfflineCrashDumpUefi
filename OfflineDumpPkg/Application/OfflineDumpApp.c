#include <OfflineDumpWriter.h>
#include <OfflineDumpPartition.h>

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

static CHAR8 const   HelloSectionData[]      = "Hello, World!ABC:123456789abcdef";
static UINT8 const   HelloSectionDataSizes[] = {
  0, 1, 15, 16, 17, 23, 24, 25, 31, 32
};
static UINT32 const  HelloSectionCount = ARRAY_SIZE (HelloSectionDataSizes);

// Sample callback used for the HelloSection data.
static EFI_STATUS EFIAPI
MemcpyCallback (
  OUT UINT8      *pDestinationPos,
  IN void const  *pDataStart,
  IN UINTN       Offset,
  IN UINTN       Size
  )
{
  CopyMem (pDestinationPos, (UINT8 const *)pDataStart + Offset, Size);
  pDestinationPos[0] = 'X'; // Prove that the callback was used instead of CopyMem.
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS    Status;
  UINT32 const  MemorySectionSize = SIZE_16KB;
  UINT64        *MemorySection    = AllocatePool (MemorySectionSize);
  EFI_HANDLE    BlockDeviceHandle;

  if (MemorySection == NULL) {
    Print (L"AllocatePool(%u) failed\n", MemorySectionSize);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  for (UINT32 Index = 0; Index != MemorySectionSize / sizeof (*MemorySection); Index += 1) {
    MemorySection[Index] = Index;
  }

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
    .DisableBlockIo2  = FALSE,
    .ForceUnencrypted = FALSE,

    // BufferCount = 0 means use the default (currently 3).
    .BufferCount       = 0,

    // BufferMemoryLimit = 0 means use the default (currently 3MB).
    // BufferMemoryLimit = 1 means as small as possible (currently 4KB * BufferCount).
    .BufferMemoryLimit = 1,
  };
  OFFLINE_DUMP_WRITER          *DumpWriter;

  Status = OfflineDumpWriterOpen (
                                  BlockDeviceHandle,
                                  // Must not include DUMP_VALID or INSUFFICIENT_STORAGE flags -- they're automatic.
                                  0,
                                  HelloSectionCount + 1,
                                  &Options,
                                  &DumpWriter
                                  );
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterOpen() failed (%r)\n", Status);
    goto Done;
  }

  RAW_DUMP_SECTION_INFORMATION  Information;

  ZeroMem (&Information, sizeof (Information));

  for (UINT32 SectionIndex = 0; SectionIndex != HelloSectionCount; SectionIndex += 1) {
    Status = OfflineDumpWriterWriteSection (
                                            DumpWriter,
                                            // Should include DUMP_VALID flag if section is valid.
                                            // Must not include INSUFFICIENT_STORAGE flag -- it's automatic.
                                            RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                            1, // MajorVersion
                                            0, // MinorVersion
                                            RAW_DUMP_SECTION_SV_SPECIFIC,
                                            &Information,
                                            "HelloSection",
                                            MemcpyCallback,   // Use a callback instead of CopyMem.
                                            HelloSectionData, // This value will be passed to the callback.
                                            HelloSectionDataSizes[SectionIndex]
                                            );
    if (EFI_ERROR (Status)) {
      Print (L"DumpWriterWriteSection() failed (%r)\n", Status);
      (void)OfflineDumpWriterClose (DumpWriter, FALSE);
      goto Done;
    }
  }

  Information.DdrRange.Base = (UINTN)MemorySection;
  Status                    = OfflineDumpWriterWriteSection (
                                                             DumpWriter,
                                                             // Should include DUMP_VALID flag if section is valid.
                                                             // Must not include INSUFFICIENT_STORAGE flag -- it's automatic.
                                                             RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                                             1, // MajorVersion
                                                             0, // MinorVersion
                                                             RAW_DUMP_SECTION_DDR_RANGE,
                                                             &Information,
                                                             "NormalMemory",
                                                             NULL, // Use CopyMem instead of a callback.
                                                             MemorySection,
                                                             MemorySectionSize
                                                             );

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

  FreePool (MemorySection);

  Print (L"Exiting (%r)\n", Status);
  return Status;
}
