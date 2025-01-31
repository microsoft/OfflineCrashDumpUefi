#include <OfflineDumpInternal.h>
#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a " fmt, "OfflineDumpCollect:", ##__VA_ARGS__)

EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                      Status;
  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProvider = NULL;

  DEBUG_PRINT (DEBUG_INFO, "Entry\n");

  Status = gBS->LocateProtocol (&gOfflineDumpProviderProtocolGuid, NULL, (VOID **)&pProvider);
  if (EFI_ERROR (Status)) {
    DEBUG_PRINT (DEBUG_ERROR, "LocateProtocol(gOfflineDumpProviderProtocolGuid) failed (%r)\n", Status);
    goto Done;
  }

  Status = OfflineDumpCollect (pProvider);

Done:

  DEBUG_PRINT (DEBUG_INFO, "Exit (Status=%r)\n", Status);
  return Status;
}
