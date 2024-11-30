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

  OfflineDumpLib              |OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf

  # CryptoPkg

  BaseCryptLib                |CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  OpensslLib                  |CryptoPkg/Library/OpensslLib/OpensslLibAccel.inf
  IntrinsicLib                |CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf

  # MdeModulePkg

  ReportStatusCodeLib         |MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf

  # MdePkg

  BaseLib                     |MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib               |MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib                    |MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  DebugPrintErrorLevelLib     |MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib               |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib         |MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib                      |MdePkg/Library/DxePcdLib/DxePcdLib.inf
  PrintLib                    |MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RngLib                      |MdePkg/Library/DxeRngLib/DxeRngLib.inf
  UefiLib                     |MdePkg/Library/UefiLib/UefiLib.inf
  UefiApplicationEntryPoint   |MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiBootServicesTableLib    |MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiDriverEntryPoint        |MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiRuntimeServicesTableLib |MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

[LibraryClasses.X64]

  TimerLib                    |UefiCpuPkg/Library/CpuTimerLib/BaseCpuTimerLib.inf

[LibraryClasses.AARCH64]

  ArmGenericTimerCounterLib   |ArmPkg/Library/ArmGenericTimerPhyCounterLib/ArmGenericTimerPhyCounterLib.inf
  ArmLib                      |ArmPkg/Library/ArmLib/ArmBaseLib.inf
  TimerLib                    |ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.inf

[Components]

  OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf

  OfflineDumpPkg/Application/OfflineDumpApp.inf {
    <PcdsFixedAtBuild>
      # For sample, allow use of RngDxe based on BaseRngLibTimerLib.
      gEfiMdePkgTokenSpaceGuid.PcdEnforceSecureRngAlgorithms|FALSE
  }

  OfflineDumpPkg/Application/OfflineDumpBench.inf {
    <PcdsFixedAtBuild>
      # For sample, allow use of RngDxe based on BaseRngLibTimerLib.
      gEfiMdePkgTokenSpaceGuid.PcdEnforceSecureRngAlgorithms|FALSE
  }

  # For development purposes, provide a generic (insecure) RngDxe for platforms that don't have one.
  SecurityPkg/RandomNumberGenerator/RngDxe/RngDxe.inf {
    <LibraryClasses>
      RngLib|MdeModulePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf
  }

[PcdsFixedAtBuild]

  # INIT, WARN, LOAD, FS, INFO, ERROR
  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel |0x8000004F

  # INIT, WARN, LOAD, FS, INFO, ERROR
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel      |0x8000004F

  # ASSERT, PRINT, CODE, MEMORY
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask         |0x0F
