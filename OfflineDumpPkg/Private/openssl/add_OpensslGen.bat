@echo off
REM Redirects <openssl/FILE.h> to openssl generated include path.
for %%a in (%*) do echo #include ^<Library/OpensslLib/OpensslGen/include/openssl/%%a.h^>>%~dp0%%a.h
