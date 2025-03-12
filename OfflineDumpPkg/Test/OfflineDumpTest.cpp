#include "OfflineDumpTest.h"

extern "C" {
 
    #include <Uefi.h>
    #include <Library/BaseMemoryLib.h>
    #include <Library/DebugLib.h>
    #include <Library/PrintLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiLib.h>
}

static unsigned s_errorCount = 0;

static void
TestPrintLnV(wchar_t const* Prefix, char const* Format, VA_LIST Args)
{
    static CHAR16 Buffer[256];
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* const ConOut = gST->ConOut;

    Buffer[0] = 0;
    UnicodeVSPrintAsciiFormat (Buffer, sizeof(Buffer), Format, Args);

    if (ConOut)
    {
        ConOut->OutputString (ConOut, (CHAR16*)Prefix);
        ConOut->OutputString (ConOut, Buffer);
        ConOut->OutputString (ConOut, (CHAR16*)L"\r\n");
    }
}

void
TestPrintLn(wchar_t const* Prefix, char const* Format, ...)
{
    VA_LIST Args;
    VA_START(Args, Format);
    TestPrintLnV(Prefix, Format, Args);
    VA_END(Args);
}

void
TestMsg(char const* Format, ...)
{
    VA_LIST Args;
    VA_START(Args, Format);
    TestPrintLnV(L"msg: ", Format, Args);
    VA_END(Args);
}

void
TestErr(char const* Format, ...)
{
    s_errorCount += 1;

    VA_LIST Args;
    VA_START(Args, Format);
    TestPrintLnV(L"ERR: ", Format, Args);
    VA_END(Args);
}

static void
RunOneTest(char const* Name, void (*TestFunc)(void))
{
    TestPrintLn(L"TEST: ", "%a", Name);
    TestFunc();
}

extern "C" EFI_STATUS EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    #define RUN_TEST(TestName) RunOneTest(#TestName, TestName);
    ALL_TESTS(RUN_TEST)
    #undef RUN_TEST    

    if (s_errorCount != 0)
    {
        TestPrintLn(L"", "\r\nFAIL: %u error(s)", s_errorCount);
        return EFI_DEVICE_ERROR;
    }
    else
    {
        TestPrintLn(L"", "PASS");
        return EFI_SUCCESS;
    }
}
