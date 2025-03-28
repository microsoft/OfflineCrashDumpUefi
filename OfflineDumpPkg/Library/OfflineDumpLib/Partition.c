// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <OfflineDumpLib.h>
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

EFI_STATUS
FindOfflineDumpRawBlockDeviceHandleForTesting (
  OUT EFI_HANDLE  *pRawBlockDeviceHandle
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  RawBlockDeviceHandle  = NULL;
  EFI_HANDLE  *pBlockIoHandleBuffer = NULL;
  UINTN       BlockIoHandleCount    = 0;

  UINT8   *pBlock0    = NULL;
  UINT32  Block0Size  = 0;
  UINT32  Block0Align = 0;

  Status = gBS->LocateHandleBuffer (
                                    ByProtocol,
                                    &gEfiBlockIoProtocolGuid,
                                    NULL,
                                    &BlockIoHandleCount,
                                    &pBlockIoHandleBuffer
                                    );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "LocateHandleBuffer(BlockIoProtocol) failed (%r)\n", Status);
  } else {
    UINT32  RawBlockDeviceCount = 0;
    for (UINTN HandleIndex = 0; HandleIndex != BlockIoHandleCount; HandleIndex += 1) {
      EFI_HANDLE  const  BlockIoHandle = pBlockIoHandleBuffer[HandleIndex];

      EFI_BLOCK_IO_PROTOCOL  *pBlockIo = NULL;
      Status = gBS->OpenProtocol (
                                  BlockIoHandle,
                                  &gEfiBlockIoProtocolGuid,
                                  (VOID **)&pBlockIo,
                                  gImageHandle,
                                  NULL,
                                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                  );
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_WARN, "OpenProtocol(BlockIoProtocol) failed (%r) for device %p\n", Status, BlockIoHandle);
        continue;
      }

      if (pBlockIo->Media->LogicalPartition) {
        DEBUG_PRINT (DEBUG_INFO, "Device %p is unusable (logical partition)\n", BlockIoHandle);
        continue;
      }

      if (pBlockIo->Media->ReadOnly) {
        DEBUG_PRINT (DEBUG_INFO, "Device %p is unusable (read-only)\n", BlockIoHandle);
        continue;
      }

      // Skip if the device contains a valid partition table.

      if ((pBlockIo->Media->BlockSize > Block0Size) ||
          (pBlockIo->Media->IoAlign > Block0Align))
      {
        if (pBlock0) {
          FreeAlignedPages (pBlock0, EFI_SIZE_TO_PAGES (Block0Size));
          pBlock0     = 0;
          Block0Size  = 0;
          Block0Align = 0;
        }

        pBlock0 = AllocateAlignedPages (
                                        EFI_SIZE_TO_PAGES (pBlockIo->Media->BlockSize),
                                        pBlockIo->Media->IoAlign
                                        );
        if (!pBlock0) {
          DEBUG_PRINT (DEBUG_ERROR, "AllocateAlignedPages(%u, %u) failed\n", pBlockIo->Media->BlockSize, pBlockIo->Media->IoAlign);
          Status = EFI_OUT_OF_RESOURCES;
          break;
        }

        Block0Size  = pBlockIo->Media->BlockSize;
        Block0Align = pBlockIo->Media->IoAlign;
      }

      Status = pBlockIo->ReadBlocks (
                                     pBlockIo,
                                     pBlockIo->Media->MediaId,
                                     0,
                                     Block0Size,
                                     pBlock0
                                     );
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_WARN, "ReadBlocks(0) failed (%r) for device %p\n", Status, BlockIoHandle);
        continue;
      }

      if ((pBlock0[510] == 0x55) && (pBlock0[511] == 0xAA)) {
        DEBUG_PRINT (DEBUG_INFO, "Device %p is unusable (contains an MBR)\n", BlockIoHandle);
        continue;
      }

      EFI_PARTITION_INFO_PROTOCOL  *pPartitionInfo = NULL;
      Status = gBS->OpenProtocol (
                                  BlockIoHandle,
                                  &gEfiPartitionInfoProtocolGuid,
                                  (VOID **)&pPartitionInfo,
                                  gImageHandle,
                                  NULL,
                                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                  );
      if (!EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_INFO, "device %p is unusable (has PartitionInfo)\n", BlockIoHandle);
        continue;
      }

      RawBlockDeviceCount += 1;
      RawBlockDeviceHandle = BlockIoHandle;
      DEBUG_PRINT (DEBUG_INFO, "device %p is USABLE (raw device, not a partition)\n", BlockIoHandle);
    }

    FreePool (pBlockIoHandleBuffer);
    pBlockIoHandleBuffer = NULL;

    if (1 != RawBlockDeviceCount) {
      DEBUG_PRINT (DEBUG_ERROR, "Found %u raw block devices, expected 1\n", RawBlockDeviceCount);
      RawBlockDeviceHandle = NULL;
      Status               = EFI_NOT_FOUND;
    } else {
      Status = EFI_SUCCESS;
    }
  }

  if (pBlock0) {
    FreeAlignedPages (pBlock0, EFI_SIZE_TO_PAGES (Block0Size));
    pBlock0 = NULL;
  }

  ASSERT ((Status == EFI_SUCCESS) == (RawBlockDeviceHandle != NULL));
  *pRawBlockDeviceHandle = RawBlockDeviceHandle;
  return Status;
}
