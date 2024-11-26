#include <Library/OfflineDumpPartition.h>
#include <Guid/OfflineDumpConfig.h>

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

BOOLEAN
IsOfflineDumpPartition (
  IN EFI_PARTITION_INFO_PROTOCOL const  *pPartitionInfo
  )
{
  BOOLEAN  Result;

  if (pPartitionInfo->Type != PARTITION_TYPE_GPT) {
    Result = FALSE;
  } else {
    Result = CompareGuid (&pPartitionInfo->Info.Gpt.PartitionTypeGUID, &gOfflineDumpPartitionTypeGuid);
  }

  return Result;
}

EFI_STATUS
GetOfflineDumpPartitionHandle (
  OUT EFI_HANDLE  *pBlockDeviceHandle
  )
{
  EFI_STATUS  Status;
  UINT32      BlockDeviceCount  = 0;
  EFI_HANDLE  BlockDeviceHandle = NULL;

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
    _DEBUG_PRINT(DEBUG_ERROR, "OD: LocateHandleBuffer(PartitionInfoProtocol) failed (%r)\n", Status);
    goto Done;
  } else {
    for (UINTN HandleIndex = 0; HandleIndex != HandleCount; HandleIndex += 1) {
      EFI_PARTITION_INFO_PROTOCOL  *PartitionInfo = NULL;
      Status = gBS->OpenProtocol (
                                  pHandleBuffer[HandleIndex],
                                  &gEfiPartitionInfoProtocolGuid,
                                  (VOID **)&PartitionInfo,
                                  gImageHandle,
                                  NULL,
                                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                  );
      if (EFI_ERROR (Status)) {
        _DEBUG_PRINT(DEBUG_ERROR, "OD: OpenProtocol(PartitionInfoProtocol) failed (%r) for device %p\n", Status, pHandleBuffer[HandleIndex]);
        continue;
      }

      if (!IsOfflineDumpPartition (PartitionInfo)) {
        continue;
      }

      BlockDeviceCount += 1;
      BlockDeviceHandle = pHandleBuffer[HandleIndex];
      _DEBUG_PRINT(DEBUG_ERROR, "OD: Device %p is a usable offline dump partition\n", pHandleBuffer[HandleIndex]);
    }

    FreePool (pHandleBuffer);
    pHandleBuffer = NULL;
  }

  if (1 != BlockDeviceCount) {
    _DEBUG_PRINT(DEBUG_ERROR, "OD: Found %u offline dump partitions, expected 1\n", BlockDeviceCount);
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:

  *pBlockDeviceHandle = EFI_ERROR (Status) ? NULL : BlockDeviceHandle;
  return Status;
}
