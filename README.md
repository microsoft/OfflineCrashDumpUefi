# Offline Crash Dump UEFI

- **[Data structures](OfflineDumpPkg/Include/Guid/)** - headers with GUIDs, enums, and structs used in
  offline crash dumps.

- **[OfflineDumpLib](OfflineDumpPkg/Include/Library/OfflineDumpLib.h)** --
  support code for writing offline crash dumps.

  - Helpers for locating the partition where the dump should be written.
  - Helpers for executing the "OfflineDumpCollect.efi" application.
  - Helpers for reading Windows-defined UEFI variables related to offline crash dumps.

- **[OfflineDumpCollectLib](OfflineDumpPkg/Include/Library/OfflineDumpCollectLib.h)** --
  static library that implements crash dump collection.

- **[Redistributable](OfflineDumpPkg/Application/OfflineDumpCollect.inf)** --
  application binary "OfflineDumpCollect.efi" that implements crash dump collection.

- **[Sample](OfflineDumpPkg/Application/OfflineDumpSampleApp.c)** -- sample shows how to generate an offline
  crash dump using `OfflineDumpCollect`.

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
    - If you usually want to build a standalone OfflineDumpSampleApp.efi module, set it to `OfflineDumpPkg/OfflineDumpPkg.dsc`.

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
    - If you usually want to build a standalone OfflineDumpSampleApp.efi module, set it to `OfflineDumpPkg/OfflineDumpPkg.dsc`.

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

The `OfflineDumpSampleApp.efi` sample app will do the following:

- Look for an appropriate target for the dump, e.g. GPT partition with Type = SVRawDump.
- If a target is found, look for the necessary UEFI variables that control dump enablement and encryption.
- If the variables are found, write a "sample" dump to the partition.

## Configuring EmulatorPkg on Windows

If using EmulatorPkg to test the application, you'll probably want to configure the Emulator as follows:

Edit `edk2\EmulatorPkg\EmulatorPkg.dsc` to build the OfflineDump library and sample application.

- Under `[LibraryClasses]`, add: `OfflineDumpLib|OfflineDumpPkg/Library/OfflineDumpLib/OfflineDumpLib.inf`
- Under `[LibraryClasses]`, add: `OfflineDumpCollectLib|OfflineDumpPkg/Library/OfflineDumpCollectLib/OfflineDumpCollectLib.inf`
- Under `[Components]`, add: `OfflineDumpPkg/Application/OfflineDumpSampleApp.inf`
- Optional: Under `[PcdsFixedAtBuild]`, add: `gOfflineDumpTokenSpaceGuid.PcdOfflineDumpUsePartition|FALSE`
  - This makes the application write directly to `disk.dmg` rather than looking for a GPT partition within `disk.dmg`.
    This allows you to treat `disk.dmg` directly as a `rawdump.bin` file without any kind of extraction step.

You may then run `build -p EmulatorPkg/EmulatorPkg.dsc` to build the EmulatorPkg platform, resulting in
platform files in a directory like `ROOT\workspace\Build\EmulatorX64\DEBUG_VS2022\X64`.

You will need to create a `workspace\Build\EmulatorX64\DEBUG_VS2022\X64\disk.dmg` file that will act as
the partition to receive the dump file. Use any tool (e.g. hex editor or dd) to create a zero-filled
file large enough to contain the dump (generally a little bit larger than the emulator's physical memory,
e.g. 129MB if the emulator is configured for 128MB of memory), e.g.
`dd if=/dev/zero of=disk.dmg bs=1M count=129`

You may want to copy the firmware variables setup script to that directory, i.e. from repo root, run:
`copy OfflineDumpPkg\dumpvars.nsh workspace\Build\EmulatorX64\DEBUG_VS2022\X64`

You can then run the resulting WinHost.exe to launch the emulator, and then in the shell, run the app:

- In the UEFI shell, change to the FS0 drive: `FS0:`
- If needed, set up the UEFI variables by running `.\dumpvars.nsh`.
- Run the sample application: `.\OfflineDumpSampleApp.efi`
  - Note that diagnostic output goes to the debug console instead of the shell console.
  - If the output says `Dump disabled`, run the `dumpvars.nsh` script to set up the variables
    and then try again.
- Close the emulator.
- The dump will be present in the disk image file, e.g. `workspace\Build\EmulatorX64\DEBUG_VS2022\X64\disk.dmg`.
  - If encrypted, you can decrypt using the sample private key from `sample_keys.pfx` (password `abc123`).

Note that there have been several recent bug fixes in EmulatorPkg. The OfflineDump code assumes that
these bugs have been fixed. You may encounter hangs or errors if using an old version of EmulatorPkg.

## Future Directions

At present, `OfflineDumpCollect` is available as a function in
OfflineDumpCollectLib or as the binary application `OfflineDumpCollect.efi`. In
the future, OfflineDumpCollectLib will no longer be available.  Users should
transition to using the `OfflineDumpCollect.efi` binary application and invoking
it using an `OfflineDumpCollectExecute` helper function.

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
