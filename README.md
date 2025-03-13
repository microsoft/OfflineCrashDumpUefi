# Offline Crash Dump UEFI

This project contains definitions and code to aid firmware developers in their implementation of
[Offline Crash Dump](#background) (OffCD).

The provided definitions (constants and data structures) may be useful for any build or execution
environment.

- **[Constants and data structures](OfflineDumpPkg/Include/Guid/)** - headers with GUIDs, enums, and
  structs used in offline crash dumps.

The provided code is intended to build in EDK2 and execute in a UEFI-DXE environment. For those using other
build or execution environments, the code may still be useful as a reference.

- **[OfflineDumpLib](OfflineDumpPkg/Include/Library/OfflineDumpLib.h)** --
  support code for writing offline crash dumps.

  - Helpers for locating the partition where the dump should be written.
  - Helpers for executing the "OfflineDumpWrite.efi" application.
  - Helpers for reading Windows-defined UEFI variables related to offline crash dumps.

- **[OfflineDumpWriterLib](OfflineDumpPkg/Include/Library/OfflineDumpWriterLib.h)** --
  static library that implements crash dump generation.

- **[Redistributable](OfflineDumpPkg/Application/OfflineDumpWrite.inf)** --
  application binary "OfflineDumpWrite.efi" that implements crash dump generation.

- **[Sample](OfflineDumpPkg/Application/OfflineDumpSampleApp.c)** -- sample shows how to generate an offline
  crash dump using `OfflineDumpWrite.efi`.

## Background

An **Online** Crash Dump is a system memory dump written by a high-level operating system (HLOS)
like Windows or Linux. An **Offline** Crash Dump (OffCD) is a system memory dump written by firmware.

Online dumps are preferable in most scenarios because they can integrate more closely with the HLOS,
its device drivers, its configuration, and its security/privacy posture.

Offline dumps are useful for cases where online dumps don't work. These may include:

- Getting data from crashes that occur before the HLOS has started.
- Getting data after the system has become unstable, i.e. when a system reset is required to
  restore system stability.
- Getting data from HLOS hangs.

Offline dumps should only be used in device development scenarios (e.g. bring-up, stabilization, or
debugging). Offline dumps should not be used in retail, production, or mission-mode scenarios.
Firmware developers should enforce this by allowing offline dump collection only when the device
is configured for debugging as determined by one of the following:

- The device is debug-fused.
- The device has a device-id-specific certificate installed that enables debugging features.

The offline dump functionality may be invoked by many different triggers, including (but not
limited to):

- Watchdog timeout indicating the HLOS is hung.
- Firmware-detected error condition.
- Long power-button press that is not handled by the HLOS.

If any of these triggers are encountered while the device is not configured to collect offline
dumps, the device should instead record basic information about the problem and report the
information via
[BERT](https://uefi.org/specs/ACPI/6.5/18_Platform_Error_Interfaces.html#boot-error-record-table-bert).

Some hardware/firmware-detected errors may be recoverable or may be reportable via
HLOS-provided facilities such as [WHEA](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/).

Both online and offline dumps include facilities for attaching extra information to the dump, e.g.
the contents of a subsystem's registers or SRAM.

- For an online dump, a device driver associated with the subsystem can register a
  [Bug Check Reason Callback Routine](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/writing-a-bug-check-callback-routine).
  This callback can gather subsystem state and add it to the dump.
- For an offline dump, the failure handler can copy subsystem state into a reserved region of
  memory before the reset. After the reset, the dump writer can include the data from these reserved
  regions into the dump as SV-specific sections.

## Boot procedures

To support offline dump, the firmware vendor must alter the normal boot flow to prepare for the
possibility of an offline dump and must add an alternative boot flow to write the dump.

Early in the boot sequence, the bootloader determines whether the system is
[booting normally](#booting-normally) or is
[rebooting due to an offline dump trigger](#rebooting-due-to-an-offline-dump-trigger).
It selects the appropriate boot flow based on this determination.

### Booting normally

The following steps occur if the system is booting normally (not rebooting due to an offline dump trigger).

1. During early boot (before UEFI), trusted firmware determines whether the device is in a retail or
   debug configuration based on fuse state and/or per-device-ID debug-enablement certificate.

   This value (retail or debug configuration) is recorded for use in case of a
   hardware/firmware-detected error.

2. Firmware configures watchdogs as appropriate to fire in cases of system stability issues.

3. Firmware
   [installs](https://tianocore-docs.github.io/edk2-UefiDriverWritersGuide/draft/5_uefi_services/52_services_that_uefi_drivers_rarely_use/5210_installconfigurationtable.html)
   the [Offline Dump Configuration table](OfflineDumpPkg/Include/Guid/OfflineDumpConfig.h) to
   indicate offline dump support and status to the HLOS.

4. Firmware checks the `OfflineMemoryDumpUseCapability` firmware environment variable to determine
   whether the HLOS has enabled offline dumps. This value is recorded for use in case of a
   hardware/firmware-detected error.

   If an error occurs before this value is checked, the firmware may assume that the HLOS has
   enabled offline dumps.

5. If the device is in a debug state and the HLOS has enabled offline dumps, the firmware reserves
   extra memory to support offline dump (the memory will not be available to the HLOS).

   - Memory is reserved for recording diagnostic information, e.g. to store CPU contexts.
   - Memory is reserved for use when
     [rebooting due to an offline dump trigger](#rebooting-due-to-an-offline-dump-trigger) so that
     the reboot does not overwrite memory that should be captured in the dump.

6. If the device is in a debug state and the HLOS has enabled offline dumps, the firmware should
   configure a watchdog to trigger if the power button is held for a long time (e.g. 10 seconds) so
   that the user can manually trigger an offline dump if the HLOS becomes unresponsive.

7. If a prior reset was due to a hardware/firmware-detected error, the firmware may publish tables
   for a BERT report.

At any point after step 1, a hardware/firmware-detected error may trigger the following sequence:

- If the device is not in a debug configuration (as determined in step 1) the device must not proceed
  with the remaining sequence. Instead, it must perform a cold reset (wiping memory) after optionally
  saving data for BERT or other error reports.
- If firmware has determined that the HLOS has not enabled offline dumps (as determined in step 4),
  the device should not proceed with the remaining sequence. Instead, it should perform a cold reset
  (wiping memory) after optionally saving data for BERT or other error reports.
  - If the hardware/firmware-detected error occurs prior to step 4, the firmware may proceed with the
    remaining sequence.
- The device attempts to flush CPU cache to DRAM.
- The device records diagnostic information into the memory that was reserved in step 5. This
  should include the following:
  - Information about the cause of the dump, e.g. which watchdog fired or which subsystem's
    firmware encoutered an error.
  - CPU (application processor) context information (the registers of each CPU).
  - Whether the firmware successfully flushed CPU cache to memory.
  - Registers and/or SRAM state from other subsystems.
- The device configures DRAM for self-refresh and performs any other necessary proceduress so that DRAM
  contents will be available after warm reset (e.g. saving DRAM encryption keys).
- The device saves information so that on subsequent boot, the bootloader can determine that the
  reset is due to an offline dump trigger.
- The device performs a warm reset (preserving memory). The system reboots for an
  [offline dump trigger](#rebooting-due-to-an-offline-dump-trigger).

### Rebooting due to an offline dump trigger

The following steps occur if the system is rebooting due to an offline dump trigger, not booting normally.

1. During early boot (before UEFI), trusted firmware determines whether the device is in a retail or
   debug configuration based on fuse state and/or per-device-ID debug-enablement certificate.

   If the device is in a retail configuration, it must not proceed with the remaining steps and must
   perform a cold reset (wiping memory) after optionally saving data for BERT or other error reports.

   If the necessary fuse state or certificate information is not available due to restrictions on the
   special offline-dump boot session, the firmware may use fuse/certificate state determined during
   the previous (normal) boot session so long as that value was determined by trusted firmware and
   was recorded in trusted (secured/fenced) memory.

2. To avoid overwriting memory that needs to be recorded in the dump, the firmware restricts itself to
   using only the memory that was reserved for this case (reserved by step 5 of the
   [Booting normally](#booting-normally) sequence).

3. To ensure security, the firmware only loads trusted modules and only the minimum set of modules
   needed to perform offline dump.

4. The firmware disables any functionality other than offline dump.

   - No configuration menu.
   - No shell.
   - No boot menu.
   - No boot to high-level OS.

5. The firmware checks firmware environment variables to determine dump configuration.

   - If the system is not configured to enable offline dump (e.g. if the `OfflineMemoryDumpUseCapability`
     variable is missing or 0), the device should not proceed with the remaining steps and should perform
     a cold reset after optionally saving data for BERT or other error reports.

     If the variable value is not available due to restrictions on the special offline-dump boot session,
     the firmware may use the value determined during the previous (normal) boot session.

6. The firmware displays UI indicating that a dump is in progress, e.g. "Offline dump in progress.
   Please release the power button. This should complete in 5-10 minutes."

7. The firmware writes the dump to a storage device, respecting the dump configuration specified by
   firmware environment variables `OfflineMemoryDumpUseCapability`, `OfflineMemoryDumpOsData`,
   `OfflineMemoryDumpEncryptionAlgorithm`, and `OfflineMemoryDumpEncryptionPublicKey`.

   If the variable values are not available, the firmware may use the values determined during the
   previous (normal) boot session.

   This step may be implemented using the `OfflineDumpWrite` helpers provided by this project:

   - Firmware implements the
     [OfflineDumpProvider](OfflineDumpPkg/Include/Protocol/OfflineDumpProvider.h) protocol and
     passes the protocol pointer to an `OfflineDumpWrite` function.
   - `OfflineDumpWrite` implementation configures itself based on the provided protocol and the
     relevant firmware environment variables.
   - `OfflineDumpWrite` implementation writes dump data to storage device, periodically invoking
     the protocol's ReportProgress callback.
     - The ReportProgress callback should update the UI to provide feedback to the user.

8. The firmware records offline dump status so that it can be reported in the
   [Offline Dump Configuration table](OfflineDumpPkg/Include/Guid/OfflineDumpConfig.h) provided
   in the subsequent normal boot.

9. The firmware records diagnostic data for use in a BERT report in the subsequent normal boot.

10. The firmware performs a cold reset (wiping memory). The system reboots for a
    [normal boot](#booting-normally).

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
- Under `[LibraryClasses]`, add: `OfflineDumpWriterLib|OfflineDumpPkg/Library/OfflineDumpWriterLib/OfflineDumpWriterLib.inf`
- Under `[Components]`, add: `OfflineDumpPkg/Application/OfflineDumpSampleApp.inf`
- Under `[Components]`, add: `OfflineDumpPkg/Application/OfflineDumpWrite.inf`
- Optional: Under `[PcdsFixedAtBuild]`, add: `gEfiMdeModulePkgTokenSpaceGuid.PcdMaxVariableSize|0x800`
  - This allows storing larger UEFI variables, which is required to support dump encryption certificates
    with larger public keys. The default value (0x400) is too small for RSA-3072 and RSA-4096.
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

## Integrating this package into an existing EDK2 build environment

There are currently two supported methods for integrating this package into your build
environment:

- Directly-link your dump-writer driver/application with `OfflineDumpLib` and use
  `OfflineDumpWrite.efi` as a separately-compiled binary (recommended).
- Directly-link your dump-writer driver/application with `OfflineDumpLib` and `OfflineDumpWriterLib`
  (deprecated; will be unsupported in the future).

Procedure:

1. Copy the `OfflineDumpPkg` folder to an appropriate location in your project.
   - If the location is not directly listed in `PACKAGES_PATH`, you may need to update paths
     in the INF files to refer to the actual location of `OfflineDumpPkg.dec` relative to
     the nearest directory in `PACKAGES_PATH`.
2. Create your own application or driver that will reference `OfflineDumpPkg`. Use
   `OfflineDumpPkg/Application/OfflineDumpSampleApp.c` as a reference.
   
    In the `.inf` file of your application or driver:
   - Add the path to `OfflineDumpPkg.dec` under `[Packages]`.
   - Add `OfflineDumpLib` under `[LibraryClasses]`.
   - If you will be directly-linking to `OfflineDumpWriterLib`, add `OfflineDumpWriterLib` under
     `[LibraryClasses]`.
3. In your project's `.dsc` file:
   - Add the paths to `OfflineDumpLib.inf` and `OfflineDumpWriterLib.inf` in the appropriate
     `[LibraryClasses]` section.
   - If using `OfflineDumpWrite.efi` as a separately-compiled binary, add
     the path to `OfflineDumpWrite.inf` under `[Components]`.

## Future Directions

At present, `OfflineDumpWrite` is available as a function in
OfflineDumpWriterLib or as the binary application `OfflineDumpWrite.efi`. In
the future, OfflineDumpWriterLib will no longer be available. Users should
transition to using the `OfflineDumpWrite.efi` binary application and invoking
it using an `OfflineDumpWriteExecute` helper function.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
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
