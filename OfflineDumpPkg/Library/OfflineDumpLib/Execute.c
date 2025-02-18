#include <OfflineDumpLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Uefi.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

static EFI_STATUS
OfflineDumpCollectExecute (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL        *pOfflineDumpCollectPath   OPTIONAL,
  IN VOID                            *pOfflineDumpCollectSourceBuffer OPTIONAL,
  IN UINTN                           OfflineDumpCollectSourceSize
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  CollectImageHandle = NULL;

  Status = gBS->LoadImage (
                           FALSE,
                           ParentImageHandle,
                           pOfflineDumpCollectPath,
                           pOfflineDumpCollectSourceBuffer,
                           OfflineDumpCollectSourceSize,
                           &CollectImageHandle
                           );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "LoadImage(OfflineDumpCollect.efi) failed (%r)\n", Status);
    return Status;
  }

  Status = gBS->InstallProtocolInterface (
                                          &CollectImageHandle,
                                          &gOfflineDumpProviderProtocolGuid,
                                          EFI_NATIVE_INTERFACE,
                                          pProviderProtocol
                                          );
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "InstallProtocolInterface(ProviderProtocol) failed (%r)\n", Status);
    goto Done;
  }

  Status = gBS->StartImage (CollectImageHandle, NULL, NULL);
  gBS->UninstallProtocolInterface (CollectImageHandle, &gOfflineDumpProviderProtocolGuid, pProviderProtocol);

Done:

  gBS->UnloadImage (CollectImageHandle);
  return Status;
}

EFI_STATUS
OfflineDumpCollectExecutePath (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL        *pOfflineDumpCollectPath
  )
{
  return OfflineDumpCollectExecute (pProviderProtocol, ParentImageHandle, pOfflineDumpCollectPath, NULL, 0);
}

EFI_STATUS
OfflineDumpCollectExecuteMemory (
  IN OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProviderProtocol,
  IN EFI_HANDLE                      ParentImageHandle,
  IN VOID                            *pOfflineDumpCollectSourceBuffer,
  IN UINTN                           OfflineDumpCollectSourceSize
  )
{
  return OfflineDumpCollectExecute (pProviderProtocol, ParentImageHandle, NULL, pOfflineDumpCollectSourceBuffer, OfflineDumpCollectSourceSize);
}
