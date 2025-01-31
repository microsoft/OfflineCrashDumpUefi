#include <OfflineDumpInternal.h>
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a " fmt, "OfflineDumpCollect:", ##__VA_ARGS__)

// From Guid/RngAlgorithm.h
#define EDKII_RNG_ALGORITHM_UNSAFE \
  { \
    0x869f728c, 0x409d, 0x4ab4, {0xac, 0x03, 0x71, 0xd3, 0x09, 0xc1, 0xb3, 0xf4 } \
  }

EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                      Status;
  OFFLINE_DUMP_PROVIDER_PROTOCOL  *pProvider = NULL;

  DEBUG_PRINT (DEBUG_INFO, "Entry\n");

  // Warn if the RNG algorithm is unsafe.
  GUID  RngGuid;
  Status = GetRngGuid (&RngGuid);
  if (EFI_ERROR (Status)) {
    // Normal - RngDxe fails GetRngGuid but that's not a problem.
    DEBUG_PRINT (DEBUG_INFO, "GetRngGuid() status %r\n", Status);
  } else {
    DEBUG_PRINT (DEBUG_INFO, "RngGuid=%g\n", &RngGuid);
    if (CompareGuid (&RngGuid, &gEdkiiRngAlgorithmUnSafe)) {
      DEBUG_PRINT (DEBUG_WARN, "RngGuid is gEdkiiRngAlgorithmUnSafe\n");
    }
  }

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
