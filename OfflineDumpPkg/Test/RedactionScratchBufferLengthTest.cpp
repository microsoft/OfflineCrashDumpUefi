#include "OfflineDumpTest.h"

extern "C" {
    #include <Library/OfflineDumpLib.h>
}

static void
TestSimple(UINT64 highestPhysicalAddress, unsigned table1s, unsigned bitmaps)
{
    UINT32 expectedSize = 4 * 1024 + (table1s * 4 * 1024) + (bitmaps * 128 * 1024);
    UINT32 size = ~expectedSize;
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
    
    // Error cases: size can't fit in UINT32
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(~(UINT64)0, &size));
    TestAssert(size == MAX_UINT32);
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(MaxAddress + 4096, &size));
    TestAssert(size == MAX_UINT32);

    // Error cases: addr not aligned to PAGE_SIZE
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(0, &size));
    TestAssert(size == MAX_UINT32);
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(1, &size));
    TestAssert(size == MAX_UINT32);
    size = 0;
    TestAssert(EFI_INVALID_PARAMETER == GetOfflineDumpRedactionScratchBufferLength(4094, &size));
    TestAssert(size == MAX_UINT32);

    TestSimple(4095, 1, 1); // Minimum.
    TestSimple(0x20BFFFFFFF, 1, 33); // 131GB
    TestSimple(MaxAddress, 32, 32766); // 127.9TB
}
