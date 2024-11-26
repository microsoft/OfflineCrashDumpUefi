# Offline Crash Dump UEFI

- **[Data structures](OfflineDumpPkg/Include/Guid/)** - headers with GUIDs, enums, and structs used in
  offline crash dumps.

- **[Libraries](OfflineDumpPkg/Include/Library/)** -- support code for writing offline crash dumps.

- **[Application](OfflineDumpPkg/Application/OfflineDumpApp/)** -- sample shows how to generate an offline crash
  dump using the provided [OfflineCrashDumpWriter](OfflineDumpPkg/Include/Library/OfflineDumpWriter.h) library.

## Getting started

### First time

- As necessary, install Visual Studio compiler tools.
- As necessary, install Python 3. `python.exe` should be on your PATH.
- Get IASL and NASM. Add to the PATH as appropriate.
  - Alternative: Ensure NuGet.exe is on your path, then run `get-iasl.cmd` and `get-nasm.cmd` scripts
    to download these binaries from the Project Mu NuGet feed.
- Init submodules, e.g. from the repo root, `git submodule update --init --recursive`
- Build the tools: `odsetup rebuild`
- Update `workspace\conf\target.txt` as appropriate.
  - Update `TOOL_CHAIN_TAG` to match the version of Visual Studio that is installed, e.g. `VS2022`.
  - Update `TARGET_ARCH` as appropriate, e.g. `X64`.
  - As appropriate, set `ACTIVE_PLATFORM`. For example, leave it set to EmulatorPkg for emulator, or set
    `ACTIVE_PLATFORM` to `OfflineDumpPkg/OfflineDumpPkg.dsc` if you want.

### Every time

- Run `odsetup` to set up the environment.
- Run `build` to build the active platform.

### Normal build

The application will look for a GPT partition with Type = SVRawDump. If found, it will try to create a
dump that contains sample information.

This will fail if the required firmware variables are not set. You may want to use the
[odvars.nsh](OfflineDumpPkg/odvars.nsh) script to set the required variables.

### Emulator build

You may want to use the [odvars.nsh](OfflineDumpPkg/odvars.nsh) script to set the required firmware variables.

Configure the Emulator to test the application as follows:

Edit `edk2\EmulatorPkg\EmulatorPkg.dsc` to build the OfflineDump library and sample application.

- Under `[LibraryClasses]`, add: `OfflineDumpLib|OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf`
- Under `[PcdsFixedAtBuild]`, add: `gOfflineDumpTokenSpaceGuid.PcdDmpUsePartition|FALSE`
  - This makes the application write directly to `disk.dmg` rather than looking for a partition within `disk.dmg`.
- Under `[Components]`, add: `OfflineDumpPkg/Application/OfflineDumpApp/OfflineDumpApp.inf`
- Under `[Components]`, add: `OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf`

Edit `EmulatorPkg\EmuBlockIoDxe\EmuBlockIo.c`. In `EmuBlockIo2WriteBlocksEx`, before `return Status;`, add the
following to fix hangs due to a bug in the emulator's BlockIo2 implementation:

```C
if (Token && Token->Event && !EFI_ERROR (Status)) {
  gBS->SignalEvent (Token->Event);
}
```

Edit `EmulatorPkg\Win\Host\WinBlockIo.c`. In `WinNtBlockIoWriteBlocks`, change the type of the `BytesWritten`
variable from `UINTN` to `DWORD` to fix write failures.

## Future Directions

In the future, it is expected that the application will become usable as-is rather than a sample. The
implementor will install an OfflineDumpConfiguration protocol and the application will use it to
configure the resulting offline crash dump. The protocol will provide the following information for
use by the application:

- Required: CPU context data to be included in the dump.
- Required: Dump reason data to be included in the dump.
- Required: System information data to be included in the dump.
- Required: List of DDR_RANGE sections to be included in the dump.
- Optional: List of other sections to be included in the dump (e.g. SV_SPECIFIC).
- Optional: Override logic for locating the block device to which the dump should be written.
- Optional: Other customizations, e.g. memory management tuning parameters.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
