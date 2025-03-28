@REM Copyright (c) Microsoft Corporation. All rights reserved.
@REM SPDX-License-Identifier: BSD-2-Clause-Patent
@echo off
setlocal
set BIN=%~dp0edk2\BaseTools\Bin\Win32
set SOURCE=https://pkgs.dev.azure.com/projectmu/acpica/_packaging/mu_iasl/nuget/v3/index.json
set NAME=edk2-acpica-iasl
set VERSION=20200717.0.0

if not exist %BIN% mkdir %BIN%

nuget install %NAME% -Version %VERSION% -Source %SOURCE% -OutputDirectory %BIN% || (
    echo Failed to download iasl nuget to %BIN%.
    goto :eof
)

move /y "%BIN%\%NAME%.%VERSION%\%NAME%\Windows-x86\*.exe" "%BIN%" || (
    echo Failed to copy iasl to %BIN%.
    goto :eof
)

move /y "%BIN%\%NAME%.%VERSION%\%NAME%\Windows-x86\*.pdb" "%BIN%"

rd /s /q %BIN%\%NAME%.%VERSION%
dir %BIN%\iasl.exe
