@REM Copyright (c) Microsoft Corporation. All rights reserved.
@REM SPDX-License-Identifier: BSD-2-Clause-Patent
@echo off
setlocal
set BIN=%~dp0edk2\BaseTools\Bin\Win32
set SOURCE=https://api.nuget.org/v3/index.json
set NAME=mu_nasm
set VERSION=2.15.5

if not exist %BIN% mkdir %BIN%

nuget install %NAME% -Version %VERSION% -Source %SOURCE% -OutputDirectory %BIN% || (
    echo Failed to download nasm nuget to %BIN%.
    goto :eof
)

move /y "%BIN%\%NAME%.%VERSION%\%NAME%\Windows-x86-64\*.exe" "%BIN%" || (
    echo Failed to copy nasm to %BIN%.
    goto :eof
)

rd /s /q "%BIN%\%NAME%.%VERSION%"
dir %BIN%\nasm.exe
