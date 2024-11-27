[Defines]
  DSC_SPECIFICATION              = 0x00010005
  PLATFORM_NAME                  = OfflineDumpPkg
  PLATFORM_GUID                  = 31d0a291-66bb-48ec-98cf-821d66e2cb0a
  PLATFORM_VERSION               = 0.1
  SUPPORTED_ARCHITECTURES        = IA32|X64|AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT
  OUTPUT_DIRECTORY               = Build/OfflineDumpPkg

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]

  # OfflineDumpPkg

  OfflineDumpLib      |OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf

  # MdePkg

  BaseLib             |MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib       |MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib       |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib |MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib              |MdePkg/Library/DxePcdLib/DxePcdLib.inf
  PrintLib            |MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RngLib              |MdePkg/Library/BaseRngLib/BaseRngLib.inf
  UefiLib             |MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

  # CryptoPkg

  BaseCryptLib        |CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  OpensslLib          |CryptoPkg/Library/OpensslLib/OpensslLibAccel.inf
  IntrinsicLib        |CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf

[LibraryClasses.AARCH64]

  ArmGenericTimerCounterLib |ArmPkg/Library/ArmGenericTimerPhyCounterLib/ArmGenericTimerPhyCounterLib.inf
  ArmLib                    |ArmPkg/Library/ArmLib/ArmBaseLib.inf
  TimerLib                  |ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.inf

[LibraryClasses.IA32, LibraryClasses.X64]

  TimerLib            |UefiCpuPkg/Library/CpuTimerLib/BaseCpuTimerLib.inf

[LibraryClasses.common.UEFI_DRIVER]

  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  DebugLib            |MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  ReportStatusCodeLib |MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf

[LibraryClasses.common.UEFI_APPLICATION]

  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  DebugLib            |MdePkg/Library/UefiDebugLibStdErr/UefiDebugLibStdErr.inf

[Components]

  OfflineDumpPkg/Application/OfflineDumpApp/OfflineDumpApp.inf
  OfflineDumpPkg/Application/OfflineDumpBench/OfflineDumpBench.inf
  OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf
