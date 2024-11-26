#include <Library/OfflineDumpPartition.h>
#include <Guid/OfflineDumpConfig.h>

#include <Library/BaseMemoryLib.h>

BOOLEAN
PartitionIsSVRawDump (
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
