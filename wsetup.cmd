@echo off
pushd %~dp0

set PYTHON_COMMAND=python.exe

if not exist edk2\edksetup.bat (
    echo git submodules not updated in ROOT. Run: "git submodule update --init" in ROOT and in ROOT\edk2.
    goto :exit
)

if not exist edk2\BaseTools\Source\C\BrotliCompress\brotli\c\common\constants.h (
    echo git submodules not updated in EDK2. Run: "git submodule update --init" in ROOT\edk2.
    goto :exit
)

set WORKSPACE=%CD%\workspace
set PACKAGES_PATH=%CD%\edk2;%CD%
if not exist %WORKSPACE%\Conf mkdir %WORKSPACE%\Conf

if defined NASM_PREFIX (
    if not exist "%NASM_PREFIX%nasm.exe" (
        echo "NASM_PREFIX\nasm.exe" not found, unsetting NASM_PREFIX.
        set NASM_PREFIX=
    )
)

if defined IASL_PREFIX (
    if not exist "%IASL_PREFIX%iasl.exe" (
        echo "IASL_PREFIX\iasl.exe" not found, unsetting IASL_PREFIX.
        set IASL_PREFIX=
    )
)

if not defined NASM_PREFIX (
    if exist %CD%\edk2\BaseTools\Bin\Win32\nasm.exe (
        echo "%CD%\edk2\BaseTools\Bin\Win32\nasm.exe" found, setting NASM_PREFIX.
        set NASM_PREFIX=%CD%\edk2\BaseTools\Bin\Win32\
    )
)

if not defined IASL_PREFIX (
    if exist %CD%\edk2\BaseTools\Bin\Win32\iasl.exe (
        echo "%CD%\edk2\BaseTools\Bin\Win32\iasl.exe" found, setting IASL_PREFIX.
        set IASL_PREFIX=%CD%\edk2\BaseTools\Bin\Win32\
    )
)

call edk2\edksetup.bat %*

if not exist %EDK_TOOLS_BIN% (
    echo Tools not found. Run "%0 rebuild" to build them.
)

if not exist "%NASM_PREFIX%nasm.exe" (
    echo.
    echo NASM not found. Set NASM_PREFIX or use get-nasm.cmd to download a
    echo copy to .\BaseTools\Bin\Win32.
)

if not exist "%IASL_PREFIX%iasl.exe" (
    echo.
    echo IASL not found. Set IASL_PREFIX or use get-iasl.cmd to download a
    echo copy to .\edk2\BaseTools\Bin\Win32.
)

:exit
popd
