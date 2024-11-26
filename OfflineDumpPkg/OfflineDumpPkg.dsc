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
  OfflineDumpLib      |OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf

  BaseLib             |MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib       |MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib       |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  #DxeServicesLib      |MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  #DxeServicesTableLib |MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  MemoryAllocationLib |MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib              |MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  #PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  #PerformanceLib      |MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  PrintLib            |MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RngLib              |MdePkg/Library/BaseRngLib/BaseRngLib.inf
  #SafeIntLib          |MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  TimerLib            |MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  UefiLib             |MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  OpensslLib  |CryptoPkg/Library/OpensslLib/OpensslLibAccel.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf

[LibraryClasses.common.UEFI_DRIVER]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf

[LibraryClasses.common.UEFI_APPLICATION]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  DebugLib|MdePkg/Library/UefiDebugLibStdErr/UefiDebugLibStdErr.inf

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000040
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x1f

[Components]
  OfflineDumpPkg/Application/OfflineDumpApp/OfflineDumpApp.inf
  OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf
  #OfflineDumpPkg/Driver/OfflineDumpConfigurationSampleDxe.inf
