#include <Library/OfflineDumpWriter.h>
#include <Library/OfflineDumpPartition.h>

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>
#include <Protocol/ShellParameters.h>
#include <Protocol/Rng.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#ifdef __INTELLISENSE__
#define PcdGetBool(x)  TRUE
#endif

static void
GetLargestConventionalRegion (
  OUT UINT8 const  **ppPhysicalBase,
  OUT UINTN        *pSize
  )
{
  EFI_PHYSICAL_ADDRESS  LargestPhysicalStart = 0;
  UINT64                LargestNumberOfPages = 0;

  EFI_STATUS             Status;
  UINTN                  MemoryMapSize = 0;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap    = NULL;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;

  Status = gBS->GetMemoryMap (&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print (L"GetMemoryMap() failed (%r)\n", Status);
    return;
  }

  MemoryMap = AllocatePool (MemoryMapSize);
  if (MemoryMap == NULL) {
    Print (L"AllocatePool(MemoryMapSize = %u) failed\n", MemoryMapSize);
    return;
  }

  Status = gBS->GetMemoryMap (&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR (Status)) {
    Print (L"GetMemoryMap() failed (%r)\n", Status);
    FreePool (MemoryMap);
    return;
  }

  for (EFI_MEMORY_DESCRIPTOR *Desc = MemoryMap; (UINT8 *)Desc < (UINT8 *)MemoryMap + MemoryMapSize; Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Desc + DescriptorSize)) {
    if (Desc->Type != EfiConventionalMemory) {
      continue;
    }

    if (Desc->NumberOfPages > LargestNumberOfPages) {
      LargestPhysicalStart = Desc->PhysicalStart;
      LargestNumberOfPages = Desc->NumberOfPages;
    }
  }

  if (LargestNumberOfPages > MAX_UINTN / EFI_PAGE_SIZE) {
    LargestNumberOfPages = MAX_UINTN / EFI_PAGE_SIZE;
  }

  FreePool (MemoryMap);

  *ppPhysicalBase = (UINT8 const *)(UINTN)LargestPhysicalStart;
  *pSize          = (UINTN)LargestNumberOfPages * EFI_PAGE_SIZE;
  Print (L"PhysicalBase = %p, Size = 0x%X\n", *ppPhysicalBase, *pSize);
}

static UINT64
StrToUint64 (
  IN CHAR8 const   *pArgName,
  IN CHAR16 const  *pStr,
  IN OUT BOOLEAN   *pAllOk
  )
{
  UINT64  Value = 0;

  if ((pStr[0] == L'0') &&
      ((pStr[1] == L'x') || (pStr[1] == L'X')))
  {
    for (UINTN Digits = 0; pStr[Digits + 2]; Digits += 1) {
      CHAR16  Digit = pStr[Digits + 2];
      UINT8   DigitValue;
      if ((Digit >= L'0') && (Digit <= L'9')) {
        DigitValue = (UINT8)(Digit - L'0');
      } else if ((Digit >= L'A') && (Digit <= L'F')) {
        DigitValue = (UINT8)(Digit - L'A' + 10);
      } else if ((Digit >= L'a') && (Digit <= L'f')) {
        DigitValue = (UINT8)(Digit - L'a' + 10);
      } else {
        Print (L"Invalid hex integer for <%a>: %s\n", pArgName, pStr);
        *pAllOk = FALSE;
        return 0;
      }

      if (Value > (MAX_UINT64 - DigitValue) / 16) {
        Print (L"Hex integer for <%a> overflows: %s\n", pArgName, pStr);
        *pAllOk = FALSE;
        return 0;
      }

      Value = Value * 16 + DigitValue;
    }
  } else {
    for (UINTN Digits = 0; pStr[Digits]; Digits += 1) {
      CHAR16  Digit = pStr[Digits];
      UINT8   DigitValue;
      if ((Digit >= L'0') && (Digit <= L'9')) {
        DigitValue = (UINT8)(Digit - L'0');
      } else {
        Print (L"Invalid decimal integer for <%a>: %s\n", pArgName, pStr);
        *pAllOk = FALSE;
        return 0;
      }

      if (Value > (MAX_UINT64 - DigitValue) / 10) {
        Print (L"Decimal integer for <%a> overflows: %s\n", pArgName, pStr);
        *pAllOk = FALSE;
        return 0;
      }

      Value = Value * 10 + DigitValue;
    }
  }

  return Value;
}

static BOOLEAN
StrToBool (
  IN CHAR8 const   *pArgName,
  IN CHAR16 const  *pStr,
  IN OUT BOOLEAN   *pAllOk
  )
{
  UINT64  Value = StrToUint64 (pArgName, pStr, pAllOk);

  if (Value > 1) {
    Print (L"Invalid boolean for <%a>: %s\n", pArgName, pStr);
    *pAllOk = FALSE;
    return FALSE;
  }

  return Value != 0;
}

static UINT8
StrToUint8 (
  IN CHAR8 const   *pArgName,
  IN CHAR16 const  *pStr,
  IN OUT BOOLEAN   *pAllOk
  )
{
  UINT64  Value = StrToUint64 (pArgName, pStr, pAllOk);

  if (Value > MAX_UINT8) {
    Print (L"Invalid UINT8 for <%a>: %s\n", pArgName, pStr);
    *pAllOk = FALSE;
    return FALSE;
  }

  return (UINT8)Value;
}

static UINT32
StrToUint32 (
  IN CHAR8 const   *pArgName,
  IN CHAR16 const  *pStr,
  IN OUT BOOLEAN   *pAllOk
  )
{
  UINT64  Value = StrToUint64 (pArgName, pStr, pAllOk);

  if (Value > MAX_UINT32) {
    Print (L"Invalid UINT32 for <%a>: %s\n", pArgName, pStr);
    *pAllOk = FALSE;
    return FALSE;
  }

  return (UINT32)Value;
}

static EFI_STATUS
ShowUsage (
  void
  )
{
  Print (L"Usage:   bench <DumpSize> [ <BufferMem> <BufferCount> <NoEncrypt> <NoAsync> ]\n");
  Print (L"Example: bench 0x1000000   0x100000    8             0           0\n");
  return EFI_INVALID_PARAMETER;
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

  EFI_SHELL_PARAMETERS_PROTOCOL  *pShellParameters;

  Status = gBS->HandleProtocol (gImageHandle, &gEfiShellParametersProtocolGuid, (void **)&pShellParameters);
  if (EFI_ERROR (Status)) {
    Print (L"HandleProtocol(ShellParameters) failed (%r)\n", Status);
    return Status;
  }

  CHAR16 *const *const  Argv = pShellParameters->Argv;
  UINTN                 Argc = pShellParameters->Argc;
  UINTN                 ArgI = 1;

  if (Argc <= ArgI) {
    return ShowUsage ();
  }

  BOOLEAN        AllOk       = TRUE;
  UINT64 const   DumpSize    = StrToUint64 ("DumpSize", Argv[ArgI++], &AllOk);
  UINT32 const   BufferMem   = Argc <= ArgI ? 0u : StrToUint32 ("BufferMem", Argv[ArgI++], &AllOk);
  UINT8 const    BufferCount = Argc <= ArgI ? 0u : StrToUint8 ("BufferCount", Argv[ArgI++], &AllOk);
  BOOLEAN const  NoEncrypt   = Argc <= ArgI ? 0u : StrToBool ("NoEncrypt", Argv[ArgI++], &AllOk);
  BOOLEAN const  NoAsync     = Argc <= ArgI ? 0u : StrToBool ("NoAsync", Argv[ArgI++], &AllOk);

  if (!AllOk) {
    return ShowUsage ();
  }

  {
    UINT64  StartValue, EndValue;
    UINT64  Frequency = GetPerformanceCounterProperties (&StartValue, &EndValue);
    Print (
           L"Timestamp info: Freq=%llu Start=0x%llX End=0x%llX\n",
           (unsigned long long)Frequency,
           (unsigned long long)StartValue,
           (unsigned long long)EndValue
           );
  }

  UINT8 const  *pPhysicalBase;
  UINTN        PhysicalSize;

  GetLargestConventionalRegion (&pPhysicalBase, &PhysicalSize);

  Status = PcdGetBool (PcdOfflineDumpUsePartition)
           // For normal usage: Look for GPT partition with Type = OFFLINE_DUMP_PARTITION_GUID.
    ? FindOfflineDumpPartitionHandle (&BlockDeviceHandle)
           // For testing on Emulator: Look for a raw block device that is not a partition.
    : FindOfflineDumpRawBlockDeviceHandleForTesting (&BlockDeviceHandle);
  if (EFI_ERROR (Status)) {
    Print (L"Find offline dump device failed (%r)\n", Status);
    goto Done;
  }

  UINT32 const  SectionCount = (UINT32)(DumpSize / PhysicalSize + 1);

  UINT64 const  TimeStart = GetPerformanceCounter ();

  OFFLINE_DUMP_WRITER_OPTIONS  Options = {
    .DisableBlockIo2   = NoAsync,
    .ForceUnencrypted  = NoEncrypt,
    .BufferCount       = BufferCount,
    .BufferMemoryLimit = BufferMem
  };
  OFFLINE_DUMP_WRITER          *DumpWriter;

  Status = OfflineDumpWriterOpen (
                                  BlockDeviceHandle,
                                  0,
                                  SectionCount,
                                  &Options,
                                  &DumpWriter
                                  );
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterOpen() failed (%r)\n", Status);
    goto Done;
  }

  RAW_DUMP_SECTION_INFORMATION  Information;

  ZeroMem (&Information, sizeof (Information));

  UINT8 const  *pFakeBase = pPhysicalBase;
  UINT64       Remaining  = DumpSize;

  while (Remaining != 0) {
    UINTN const  SectionSize = (UINTN)MIN (Remaining, PhysicalSize);
    Information.DdrRange.Base = (UINT64)(UINTN)pFakeBase;
    Status                    = OfflineDumpWriterWriteSection (
                                                               DumpWriter,
                                                               RAW_DUMP_SECTION_HEADER_DUMP_VALID,
                                                               RAW_DUMP_DDR_RANGE_CURRENT_MAJOR_VERSION,
                                                               RAW_DUMP_DDR_RANGE_CURRENT_MINOR_VERSION,
                                                               RAW_DUMP_SECTION_DDR_RANGE,
                                                               &Information,
                                                               "Memory",
                                                               NULL,
                                                               pPhysicalBase,
                                                               SectionSize
                                                               );
    if (EFI_ERROR (Status)) {
      Print (L"DumpWriterWriteSection() failed (%r)\n", Status);
      goto Done;
    }

    pFakeBase += SectionSize;
    Remaining -= SectionSize;
  }

  EFI_STATUS const  LastError           = OfflineDumpWriterLastWriteError (DumpWriter);
  UINT64 const      MediaPos            = OfflineDumpWriterMediaPosition (DumpWriter);
  UINT64 const      MediaSize           = OfflineDumpWriterMediaSize (DumpWriter);
  BOOLEAN  const    InsufficientStorage = OfflineDumpWriterHasInsufficientStorage (DumpWriter);

  Status = OfflineDumpWriterClose (DumpWriter, TRUE);
  if (EFI_ERROR (Status)) {
    Print (L"DumpWriterClose() failed (%r)\n", Status);
    goto Done;
  }

  if (LastError != EFI_SUCCESS) {
    Print (L"Last write error: %r\n", LastError);
  }

  if (InsufficientStorage) {
    Print (
           L"Insufficient storage (Have 0x%llX Need 0x%llX)\n",
           (unsigned long long)MediaSize,
           (unsigned long long)MediaPos
           );
  }

  if ((LastError != EFI_SUCCESS) || InsufficientStorage) {
    Status = EFI_ABORTED;
    goto Done;
  }

  UINT64 const  TimeEnd            = GetPerformanceCounter ();
  UINT64 const  TimeNS             = GetTimeInNanoSecond (TimeEnd - TimeStart);
  UINT64 const  KilobytesPerSecond = DumpSize * (1000000000 / 1024) / (TimeNS ? TimeNS : 1);

  Print (
         L"Results: %llu KB, %llu ms, %llu KB/sec\n",
         (unsigned long long)(DumpSize / 1024),
         (unsigned long long)(TimeNS / 1000000),
         (unsigned long long)KilobytesPerSecond
         );
  Status = EFI_SUCCESS;

Done:

  Print (L"Exiting (%r)\n", Status);
  return Status;
}
