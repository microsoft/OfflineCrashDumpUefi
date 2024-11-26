@echo off
REM Redirects <openssl/FILE.h> to openssl static include path.
for %%a in (%*) do echo #include ^<Library/OpensslLib/openssl/include/openssl/%%a.h^>>%~dp0%%a.h
