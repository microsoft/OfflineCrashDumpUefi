#include <Library/OfflineDumpPartition.h>
#include <Guid/OfflineDumpConfig.h>

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

BOOLEAN
HandleIsOfflineDumpPartition (
  IN EFI_HANDLE  DeviceHandle
  )
{
  EFI_STATUS  Status;

  Status = gBS->OpenProtocol (DeviceHandle, &gEfiBlockIoProtocolGuid, NULL, gImageHandle, NULL, EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (
                 DEBUG_INFO,
                 "OpenProtocol(BlockIo) failed (%r) for device %p\n",
                 Status,
                 DeviceHandle
                 );
    return FALSE;
  }

  EFI_PARTITION_INFO_PROTOCOL  *pPartitionInfo;

  Status = gBS->OpenProtocol (
                              DeviceHandle,
                              &gEfiPartitionInfoProtocolGuid,
                              (VOID **)&pPartitionInfo,
                              gImageHandle,
                              NULL,
                              EFI_OPEN_PROTOCOL_GET_PROTOCOL
                              );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (
                 DEBUG_INFO,
                 "OpenProtocol(PartitionInfo) failed (%r) for device %p\n",
                 Status,
                 DeviceHandle
                 );
    return FALSE;
  }

  if (pPartitionInfo->Type != PARTITION_TYPE_GPT) {
    DEBUG_PRINT (
                 DEBUG_INFO,
                 "device %p partition Type %u != GPT\n",
                 DeviceHandle,
                 pPartitionInfo->Type
                 );
    return FALSE;
  }

  if (!CompareGuid (&pPartitionInfo->Info.Gpt.PartitionTypeGUID, &gOfflineDumpPartitionTypeGuid)) {
    DEBUG_PRINT (
                 DEBUG_INFO,
                 "device %p PartitionTypeGUID %g != OfflineDump\n",
                 DeviceHandle,
                 &pPartitionInfo->Info.Gpt.PartitionTypeGUID
                 );
    return FALSE;
  }

  DEBUG_PRINT (DEBUG_INFO, "device %p is an OfflineDump partition\n", DeviceHandle);
  return TRUE;
}

EFI_STATUS
FindOfflineDumpPartitionHandle (
  OUT EFI_HANDLE  *pOfflineDumpDeviceHandle
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  OfflineDumpDeviceHandle = NULL;
  EFI_HANDLE  *pPartitionHandleBuffer = NULL;
  UINTN       PartitionHandleCount    = 0;

  Status = gBS->LocateHandleBuffer (
                                    ByProtocol,
                                    &gEfiPartitionInfoProtocolGuid,
                                    NULL,
                                    &PartitionHandleCount,
                                    &pPartitionHandleBuffer
                                    );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "LocateHandleBuffer(PartitionInfoProtocol) failed (%r)\n", Status);
  } else {
    UINT32  OfflineDumpDeviceCount = 0;
    for (UINTN HandleIndex = 0; HandleIndex != PartitionHandleCount; HandleIndex += 1) {
      EFI_HANDLE  const  PartitionHandle = pPartitionHandleBuffer[HandleIndex];
      if (HandleIsOfflineDumpPartition (PartitionHandle)) {
        OfflineDumpDeviceCount += 1;
        OfflineDumpDeviceHandle = PartitionHandle;
      }
    }

    FreePool (pPartitionHandleBuffer);
    pPartitionHandleBuffer = NULL;

    if (1 != OfflineDumpDeviceCount) {
      DEBUG_PRINT (DEBUG_ERROR, "Found %u offline dump partitions, expected 1\n", OfflineDumpDeviceCount);
      OfflineDumpDeviceHandle = NULL;
      Status                  = EFI_NOT_FOUND;
    } else {
      Status = EFI_SUCCESS;
    }
  }

  ASSERT ((Status == EFI_SUCCESS) == (OfflineDumpDeviceHandle != NULL));
  *pOfflineDumpDeviceHandle = OfflineDumpDeviceHandle;
  return Status;
}
