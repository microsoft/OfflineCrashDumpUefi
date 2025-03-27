// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <OfflineDumpLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Uefi.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

static EFI_STATUS
OfflineDumpWriteExecute (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL        *pOfflineDumpWritePath   OPTIONAL,
  IN VOID                            *pOfflineDumpWriteSourceBuffer OPTIONAL,
  IN UINTN                           OfflineDumpWriteSourceSize
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  WriteImageHandle = NULL;

  Status = gBS->LoadImage (
                           FALSE,
                           ParentImageHandle,
                           pOfflineDumpWritePath,
                           pOfflineDumpWriteSourceBuffer,
                           OfflineDumpWriteSourceSize,
                           &WriteImageHandle
                           );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "LoadImage(OfflineDumpWrite.efi) failed (%r)\n", Status);
    return Status;
  }

  Status = gBS->InstallProtocolInterface (
                                          &WriteImageHandle,
                                          &gOfflineDumpProviderProtocolGuid,
                                          EFI_NATIVE_INTERFACE,
                                          pProviderProtocol
                                          );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "InstallProtocolInterface(ProviderProtocol) failed (%r)\n", Status);
    goto Done;
  }

  Status = gBS->StartImage (WriteImageHandle, NULL, NULL);
  gBS->UninstallProtocolInterface (WriteImageHandle, &gOfflineDumpProviderProtocolGuid, pProviderProtocol);

Done:

  gBS->UnloadImage (WriteImageHandle);
  return Status;
}

EFI_STATUS
OfflineDumpWriteExecutePath (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL        *pOfflineDumpWritePath
  )
{
  return OfflineDumpWriteExecute (pProviderProtocol, ParentImageHandle, pOfflineDumpWritePath, NULL, 0);
}

EFI_STATUS
OfflineDumpWriteExecuteMemory (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN VOID                            *pOfflineDumpWriteSourceBuffer,
  IN UINTN                           OfflineDumpWriteSourceSize
  )
{
  return OfflineDumpWriteExecute (pProviderProtocol, ParentImageHandle, NULL, pOfflineDumpWriteSourceBuffer, OfflineDumpWriteSourceSize);
}
