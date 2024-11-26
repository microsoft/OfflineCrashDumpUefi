#include <Library/OfflineDumpWriter.h>
#include <Library/OfflineDumpPartition.h>

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>

static EFI_STATUS
LocateDumpDevice (
  IN EFI_HANDLE   ImageHandle,
  OUT EFI_HANDLE  *pBlockDeviceHandle
  )
{
  EFI_STATUS  Status;
  UINT32      BlockDeviceCount  = 0;
  EFI_HANDLE  BlockDeviceHandle = NULL;

  if (PcdGetBool (PcdDmpUsePartition)) {
    // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
    EFI_HANDLE  *pHandleBuffer = NULL;
    UINTN       HandleCount    = 0;
    Status = gBS->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiPartitionInfoProtocolGuid,
                                      NULL,
                                      &HandleCount,
                                      &pHandleBuffer
                                      );
    if (EFI_ERROR (Status)) {
      Print (L"LocateHandleBuffer(PartitionInfoProtocol) failed (%r)\n", Status);
      goto Done;
    } else {
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
        if (EFI_ERROR (Status)) {
          Print (L"OpenProtocol(PartitionInfoProtocol) failed (%r) for device %u\n", Status, HandleIndex);
          continue;
        }

        if (!PartitionIsSVRawDump (PartitionInfo)) {
          continue;
        }

        BlockDeviceCount += 1;
        BlockDeviceHandle = pHandleBuffer[HandleIndex];
        Print (L"Partition %u is a usable dump target\n", HandleIndex);
      }

      FreePool (pHandleBuffer);
      pHandleBuffer = NULL;
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
      Print (L"LocateHandleBuffer(BlockIoProtocol) failed (%r)\n", Status);
    } else {
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
          Print (L"OpenProtocol(PartitionInfoProtocol) succeeded for device %u, so not using it.\n", HandleIndex);
          continue;
        }

        // TODO: Skip if the device contains a valid partition table.

        BlockDeviceCount += 1;
        BlockDeviceHandle = pHandleBuffer[HandleIndex];
        Print (L"Device %u is usable (raw device, not a partition)\n", HandleIndex);
      }

      FreePool (pHandleBuffer);
      pHandleBuffer = NULL;
    }
  }

  if (1 != BlockDeviceCount) {
    Print (L"Expected 1 applicable block device, found %u\n", BlockDeviceCount);
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:

  *pBlockDeviceHandle = EFI_ERROR (Status) ? NULL : BlockDeviceHandle;
  return Status;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
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
    .BufferMemoryLimit = 0
  };
  DUMP_WRITER          *DumpWriter;
  Status = DumpWriterOpen (
                           BlockDeviceHandle,
                           0,
                           20,
                           &Options,
                           &DumpWriter
                           );
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterOpen() failed (%r)\n", Status);
    goto Done;
  }

  for (unsigned i = 0; i != 20; i += 1) {
    static UINT8 const            SectionData[] = "Hello, world!";
    RAW_DUMP_SECTION_INFORMATION  Information;
    ZeroMem (&Information, sizeof (Information));
    Status = DumpWriterWriteSection (
                                     DumpWriter,
                                     RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                     1,
                                     0,
                                     RAW_DUMP_SECTION_SV_SPECIFIC,
                                     &Information,
                                     "012345678901234567890",
                                     NULL,
                                     SectionData,
                                     sizeof (SectionData)
                                     );
    if (EFI_ERROR (Status)) {
      Print (L"DumpWriterWriteSection() failed (%r) for section %u\n", Status, i);
      goto Done;
    }
  }

  Status = DumpWriterClose (DumpWriter, TRUE);
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterClose() failed (%r)\n", Status);
    goto Done;
  }

Done:

  Print (L"Exiting (%r)\n", Status);
  return Status;
}
