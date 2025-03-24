#include "OfflineDumpTest.h"

extern "C" {
    #include <Library/OfflineDumpLib.h>
}

static void
TestSimple(UINT64 highestPhysicalAddress, unsigned table1s, unsigned bitmaps)
{
    UINT32 expectedSize = 4 * 1024 + (table1s * 4 * 1024) + (bitmaps * 128 * 1024);
    UINT32 size;
    TestAssert(EFI_SUCCESS == GetOfflineDumpRedactionScratchBufferLength(highestPhysicalAddress, &size));
    if (size != expectedSize) {
        TestErr("RedactionScratchBufferLength: address 0x%llX, expected 0x%X, actual 0x%X",
             (unsigned long long)highestPhysicalAddress, expectedSize, size);
    }
}

void
RedactionScratchBufferLengthTest()
{
    static UINT64 const MaxAddress = 0x7FFDFFFFFFFF;
    UINT32 size;
    
    // Test error cases (size can't fit in UINT32)
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(~(UINT64)0, &size));
    TestAssert(size == 0xFFFFF000);
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(MaxAddress + 1, &size));
    TestAssert(size == 0xFFFFF000);

    TestSimple(0, 1, 1); // Minimum.
    TestSimple(0x20BFFFFFFF, 1, 33); // 131GB
    TestSimple(MaxAddress, 32, 32766); // 127.9TB
}
