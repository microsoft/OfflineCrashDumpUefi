#include <Library/OfflineDumpVariables.h>

#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

static UINT32 const  mOfflineDumpEncryptionPublicKeyMaxSize = 0x10000;

EFI_STATUS
OfflineMemoryDumpUseCapability (
  OUT OFFLINE_DUMP_USE_CAPABILITY_FLAGS  *pFlags
  )
{
  EFI_STATUS  Status;
  UINT32      Data     = 0;
  UINTN       DataSize = sizeof (Data);

  Status = gST->RuntimeServices->GetVariable (
                                              OFFLINE_DUMP_USE_CAPABILITY_VARIABLE_NAME,
                                              &gOfflineDumpVendorGuid,
                                              NULL,
                                              &DataSize,
                                              &Data
                                              );
  *pFlags = Data;
  return Status;
}

EFI_STATUS
OfflineMemoryDumpOsData (
  OUT UINT64  *pOsData
  )
{
  EFI_STATUS  Status;
  UINT64      Data     = 0;
  UINTN       DataSize = sizeof (Data);

  Status = gST->RuntimeServices->GetVariable (
                                              OFFLINE_DUMP_OS_DATA_VARIABLE_NAME,
                                              &gOfflineDumpVendorGuid,
                                              NULL,
                                              &DataSize,
                                              &Data
                                              );
  *pOsData = Data;
  return Status;
}

EFI_STATUS
OfflineMemoryDumpEncryptionAlgorithm (
  OUT ENC_DUMP_ALGORITHM  *pAlgorithm
  )
{
  EFI_STATUS  Status;
  UINT32      Data     = 0;
  UINTN       DataSize = sizeof (Data);

  Status = gST->RuntimeServices->GetVariable (
                                              OFFLINE_DUMP_ENCRYPTION_ALGORITHM_VARIABLE_NAME,
                                              &gOfflineDumpVendorGuid,
                                              NULL,
                                              &DataSize,
                                              &Data
                                              );
  *pAlgorithm = Data;
  return Status;
}

EFI_STATUS
OfflineMemoryDumpEncryptionPublicKey (
  OUT void    **ppRecipientCertificate,
  OUT UINT32  *pRecipientCertificateSize
  )
{
  EFI_STATUS  Status;
  void        *pData;
  UINTN       DataSize = 0;

  Status = gST->RuntimeServices->GetVariable (
                                              OFFLINE_DUMP_ENCRYPTION_PUBLIC_KEY_VARIABLE_NAME,
                                              &gOfflineDumpVendorGuid,
                                              NULL,
                                              &DataSize,
                                              NULL
                                              );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    if (!EFI_ERROR (Status)) {
      Status = EFI_NOT_FOUND;
    }

    pData    = NULL;
    DataSize = 0;
  } else if (DataSize >= mOfflineDumpEncryptionPublicKeyMaxSize) {
    Status   = EFI_BAD_BUFFER_SIZE;
    pData    = NULL;
    DataSize = 0;
  } else {
    pData = AllocatePool (DataSize);
    if (pData == NULL) {
      Status   = EFI_OUT_OF_RESOURCES;
      DataSize = 0;
    } else {
      Status = gST->RuntimeServices->GetVariable (
                                                  OFFLINE_DUMP_ENCRYPTION_PUBLIC_KEY_VARIABLE_NAME,
                                                  &gOfflineDumpVendorGuid,
                                                  NULL,
                                                  &DataSize,
                                                  pData
                                                  );
      if (EFI_ERROR (Status)) {
        FreePool (pData);
        pData    = NULL;
        DataSize = 0;
      }
    }
  }

  *ppRecipientCertificate    = pData;
  *pRecipientCertificateSize = (UINT32)DataSize;
  return Status;
}
