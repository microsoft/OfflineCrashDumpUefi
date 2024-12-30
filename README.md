# Offline Crash Dump UEFI

- **[Data structures](OfflineDumpPkg/Include/Guid/)** - headers with GUIDs, enums, and structs used in
  offline crash dumps.

- **[Libraries](OfflineDumpPkg/Include/Library/)** -- support code for writing offline crash dumps.
  In particular, use [OFFLINE_DUMP_WRITER](OfflineDumpPkg/Include/Library/OfflineDumpWriter.h) to write
  dumps.

- **[Application](OfflineDumpPkg/Application/OfflineDumpApp/)** -- sample shows how to generate an offline
  crash dump using `OFFLINE_DUMP_WRITER`.

## EDK2 build environment (Windows)

### EDK2 first-time setup (Windows)

- As necessary, install Visual Studio compiler tools.
- As necessary, install Python 3. `python.exe` should be on your PATH.
- Get IASL and NASM. Add to the PATH as appropriate.
  - Alternative: Ensure NuGet.exe is on your path, then run `get-iasl.cmd` and `get-nasm.cmd` scripts
    to download these binaries from the Project Mu NuGet feed into a repo-local directory.
- Init submodules in repo root and in edk2.
  - CD to repo root and run: `git submodule update --init`
  - CD to root\edk2 and run: `git submodule update --init`
- Build the tools: `wsetup rebuild`
- Update `workspace\Conf\target.txt` as appropriate.
  - Update `TOOL_CHAIN_TAG` to match the version of Visual Studio that is installed, e.g. `VS2022`.
  - Update `TARGET_ARCH` as appropriate for your default target, e.g. `X64`.
  - As appropriate, set `ACTIVE_PLATFORM` to the platform you want to have as your default.
    - If you usually want to work in the Emulator, leave it set to `EmulatorPkg/EmulatorPkg.dsc`.
    - If you usually want to build a standalone OfflineDumpApp.efi module, set it to `OfflineDumpPkg/OfflineDumpPkg.dsc`.

### EDK2 each-time setup (Windows)

- Run `wsetup` to set up the environment.
- Run `build` to build the active platform.
- Run `build (options)` to build other platforms.

## EDK2 build environment (Linux)

### EDK2 first-time setup (Linux)

- As necessary, install basic build stuff: `apt install build-essential uuid-dev iasl nasm git python3 python-is-python3`
- As necessary, install cross-compiler: `apt install gcc-aarch64-linux-gnu`
- Init submodules in repo root and in edk2.
  - CD to repo root and run: `git submodule update --init`
  - CD to root/edk2 and run: `git submodule update --init`
- Build BaseTools: CD to repo root and run: `make -C edk2/BaseTools`
- CD to repo root and source (not run!) the environment setup script: `. usetup.sh`
  - Not `./usetup.sh`
- Update `workspace/Conf/target.txt` as appropriate.
  - Update `TOOL_CHAIN_TAG` to `GCC`
  - Update `TARGET_ARCH` as appropriate for your default target, e.g. `X64` or `AARCH64`.
  - As appropriate, set `ACTIVE_PLATFORM` to the platform you want to have as your default.
    - If you usually want to work in the Emulator, leave it set to `EmulatorPkg/EmulatorPkg.dsc`.
    - If you usually want to build a standalone OfflineDumpApp.efi module, set it to `OfflineDumpPkg/OfflineDumpPkg.dsc`.

### EDK2 each-time setup (Linux)

- Source `. usetup.sh` to set up the environment (use `. usetup.sh`, not `./usetup.sh`).
- Run `build` to build the active platform.
- Run `build (options)` to build other platforms.

## Application behavior

OfflineDump is configured using some firmware variables. For testing purposes, you will need to set
these variables before running the sample app.

- Use the [dumpvars.nsh](OfflineDumpPkg/dumpvars.nsh) script to configure the device.
  - This sets OfflineMemoryDumpUseCapability = 1 (enable dumps).
  - This sets OfflineMemoryDumpEncryptionAlgorithm to 0 (no encryption), 1 (AES128), 2 (AES192), or 3 (AES256).
  - This sets OfflineMemoryDumpEncryptionPublicKey to the certificate from `sample_keys.cer`.
  - The private key corresponding to `sample_keys.cer` is provided in `sample_keys.pfx` (password `abc123`).

The `OfflineDumpApp.efi` sample app will do the following:

- Look for an appropriate target for the dump, e.g. GPT partition with Type = SVRawDump.
- If a target is found, look for the necessary UEFI variables that control dump enablement and encryption.
- If the variables are found, write a "sample" dump to the partition.

## Configuring EmulatorPkg on Windows

If using EmulatorPkg to test the application, you'll probably want to configure the Emulator as follows:

Edit `edk2\EmulatorPkg\EmulatorPkg.dsc` to build the OfflineDump library and sample application.

- Under `[LibraryClasses]`, add: `OfflineDumpLib|OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf`
- Under `[PcdsFixedAtBuild]`, add: `gOfflineDumpTokenSpaceGuid.PcdDmpUsePartition|FALSE`
  - This makes the application write directly to `disk.dmg` rather than looking for a GPT partition within `disk.dmg`.
    This allows you to treat `disk.dmg` directly as a `rawdump.bin` file without any kind of extraction step.
- Under `[Components]`, add: `OfflineDumpPkg/Application/OfflineDumpApp/OfflineDumpApp.inf`
- Under `[Components]`, add: `OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf`

You may then run `build -p EmulatorPkg/EmulatorPkg.dsc` to build the EmulatorPkg platform, resulting in
platform files in a directory like `ROOT\workspace\Build\EmulatorX64\DEBUG_VS2022\X64`.

You may want to copy the firmware setup variables to that directory, i.e. from repo root, run:
`copy OfflineDumpPkg\dumpvars.nsh workspace\Build\EmulatorX64\DEBUG_VS2022\X64`

You can then run the resulting WinHost.exe to launch the emulator, and then in the shell, run the app:

- In the UEFI shell, change to the FS0 drive: `FS0:`
- If needed, set up the UEFI variables by running `.\dumpvars.nsh`.
- Run the sample application: `.\OfflineDumpApp.efi`
- Note that some of the output goes to the debug console, not the shell console.
- Close the emulator.
- The dump will be present in the disk image file, `workspace\Build\EmulatorX64\DEBUG_VS2022\X64\disk.dmg`.
  - If encrypted, you can decrypt using the sample private key from `sample_keys.pfx` (password `abc123`).

Note that there have been several recent bug fixes in EmulatorPkg. The OfflineDump code assumes that
these bugs have been fixed. You may encounter hangs or errors if using an old version of EmulatorPkg.

## Future Directions

At present, the `OFFLINE_DUMP_WRITER` class is the top layer of the provided library. To create a dump,
you construct a `OFFLINE_DUMP_WRITER`, write sections, and close the dump writer.

In the future, the `OFFLINE_DUMP_WRITER` will become a private implementation detail. The top layer of the
library will be a single `WriteDump` function that takes a `pDumpConfigurationProtocol` parameter.
`pDumpConfigurationProtocol` will point to a structure with all of the information needed to write the dump:

- Required: CPU context data to be included in the dump.
- Required: Dump reason data to be included in the dump.
- Required: System information data to be included in the dump.
- Required: List of DDR_RANGE sections to be included in the dump.
- Required: Progress callback (to blink a progress LED or update the screen).
- Optional: Redaction list for Secure Kernel memory.
- Optional: List of other sections to be included in the dump (e.g. SV_SPECIFIC).
- Optional: Custom rules for locating the block device to which the dump should be written.
- Optional: Other customizations, e.g. memory management tuning parameters.

In the future, this functionality may be distributed as a binary EFI application rather than as source
code. The implementor will install an OfflineDumpConfiguration protocol and the application will use
it to configure the resulting offline crash dump.

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
