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

static EFI_STATUS
LocateDumpDevice (
  IN EFI_HANDLE   ImageHandle,
  OUT EFI_HANDLE  *pBlockDeviceHandle
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  BlockDeviceHandle = NULL;

  if (PcdGetBool (PcdDmpUsePartition)) {
    // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
    Status = GetOfflineDumpPartitionHandle (&BlockDeviceHandle);
    if (EFI_ERROR (Status)) {
      _DEBUG_PRINT (DEBUG_ERROR, "OD: GetOfflineDumpPartitionHandle() failed (%r)\n", Status);
    }
  } else {
    // For testing on Emulator: Look for raw block device that is not a partition.
    EFI_HANDLE  *pHandleBuffer = NULL;
    UINTN       HandleCount    = 0;
    Status = gBS->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiBlockIoProtocolGuid,
                                      NULL,
                                      &HandleCount,
                                      &pHandleBuffer
                                      );
    if (EFI_ERROR (Status)) {
      _DEBUG_PRINT (DEBUG_ERROR, "OD: LocateHandleBuffer(BlockIoProtocol) failed (%r)\n", Status);
    } else {
      UINT32  BlockDeviceCount = 0;
      for (UINTN HandleIndex = 0; HandleIndex != HandleCount; HandleIndex += 1) {
        EFI_PARTITION_INFO_PROTOCOL  *PartitionInfo = NULL;
        Status = gBS->OpenProtocol (
                                    pHandleBuffer[HandleIndex],
                                    &gEfiPartitionInfoProtocolGuid,
                                    (VOID **)&PartitionInfo,
                                    ImageHandle,
                                    NULL,
                                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                    );
        if (!EFI_ERROR (Status)) {
          _DEBUG_PRINT (DEBUG_INFO, "OD: OpenProtocol(PartitionInfoProtocol) succeeded for device %p, so not using it.\n", pHandleBuffer[HandleIndex]);
          continue;
        }

        // TODO: Skip if the device contains a valid partition table.

        BlockDeviceCount += 1;
        BlockDeviceHandle = pHandleBuffer[HandleIndex];
        _DEBUG_PRINT (DEBUG_INFO, "OD: Device %p is usable (raw device, not a partition)\n", pHandleBuffer[HandleIndex]);
      }

      FreePool (pHandleBuffer);
      pHandleBuffer = NULL;

      if (1 == BlockDeviceCount) {
        ASSERT (BlockDeviceHandle != NULL);
        Status = EFI_SUCCESS;
      } else {
        _DEBUG_PRINT (DEBUG_ERROR, "OD: Expected 1 applicable block device, found %u\n", BlockDeviceCount);
        BlockDeviceHandle = NULL;
        Status            = EFI_NOT_FOUND;
      }
    }
  }

  *pBlockDeviceHandle = BlockDeviceHandle;
  return Status;
}

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

  Status = LocateDumpDevice (ImageHandle, &BlockDeviceHandle);
  if (EFI_ERROR (Status)) {
    Print (L"LocateDumpDevice() failed (%r)\n", Status);
    goto Done;
  }

  DUMP_WRITER_OPTIONS  Options = {
    .DisableBlockIo2   = FALSE,
    .ForceUnencrypted  = FALSE,
    .BufferCount       = 0,
    .BufferMemoryLimit = 0,
  };
  DUMP_WRITER          *DumpWriter;
  Status = DumpWriterOpen (
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
    Status = DumpWriterWriteSection (
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

  EFI_STATUS const  LastError           = DumpWriterLastWriteError (DumpWriter);
  UINT64 const      MediaPos            = DumpWriterMediaPosition (DumpWriter);
  UINT64 const      MediaSize           = DumpWriterMediaSize (DumpWriter);
  BOOLEAN  const    InsufficientStorage = DumpWriterHasInsufficientStorage (DumpWriter);

  Status = DumpWriterClose (DumpWriter, TRUE);
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
