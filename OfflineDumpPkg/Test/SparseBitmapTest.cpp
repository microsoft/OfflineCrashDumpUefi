#include "OfflineDumpTest.h"
#include <Library/OfflineDumpRedactionMap.h>
#include <Library/OfflineDumpRedactionMapInternal.h>

static UINT64 g_mapBuf[1024 * 1024 / sizeof(UINT64)]; // 1MB

void
OfflineDumpRedactionMap_Init_Test()
{
    OFFLINE_DUMP_REDACTION_MAP map;
    TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, sizeof(g_mapBuf), MAX_BITS_PER_TABLE0 + 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 - 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 1));
    TestAssert(EFI_OUT_OF_RESOURCES == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, 64 * 1024 - 1, MAX_BITS_PER_TABLE0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 - 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 1));
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, 64 * 1024, MAX_BITS_PER_TABLE0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 - 1));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 0));
    TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, MAX_BITS_PER_TABLE0 + 1));
}

static void
ClearAndCheck(OFFLINE_DUMP_REDACTION_MAP& map, UINT64 beginPageNum, UINT64 endPageNum)
{
    TestAssert(beginPageNum <= endPageNum);
    auto const beforeWasSet = OfflineDumpRedactionMap_IsRedacted(&map, beginPageNum - 1);
    auto const afterWasSet = OfflineDumpRedactionMap_IsRedacted(&map, endPageNum);
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, beginPageNum, endPageNum));
    TestAssert(beforeWasSet == OfflineDumpRedactionMap_IsRedacted(&map, beginPageNum - 1));
    TestAssert(afterWasSet == OfflineDumpRedactionMap_IsRedacted(&map, endPageNum));

    auto range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum, endPageNum);
    TestAssert(range.BeginRedactedPageNum == endPageNum);
    TestAssert(range.EndRedactedPageNum == endPageNum);

    if (beginPageNum - 1 < beginPageNum)
    {
        range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum - 1, endPageNum);
        TestAssert(range.BeginRedactedPageNum == beforeWasSet ? beginPageNum - 1 : endPageNum);
        TestAssert(range.EndRedactedPageNum == beforeWasSet ? beginPageNum : endPageNum);
    }

    if (endPageNum < endPageNum + 1)
    {
        range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum, endPageNum + 1);
        TestAssert(range.BeginRedactedPageNum == afterWasSet ? endPageNum : endPageNum);
        TestAssert(range.EndRedactedPageNum == afterWasSet ? endPageNum + 1 : endPageNum);
    }


    if (endPageNum - beginPageNum < 256)
    {
        for (UINT64 pageNum = beginPageNum; pageNum != endPageNum; pageNum += 1)
        {
            TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
    }
    else
    {
        for (UINT64 pageNum = beginPageNum; pageNum != beginPageNum + 128; pageNum += 1)
        {
            TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
        for (UINT64 pageNum = endPageNum - 128; pageNum != endPageNum; pageNum += 1)
        {
            TestAssert(!OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
    }
}

static void
SetAndCheck(OFFLINE_DUMP_REDACTION_MAP& map, UINT64 beginPageNum, UINT64 endPageNum)
{
    TestAssert(beginPageNum <= endPageNum);
    auto const beforeWasSet = OfflineDumpRedactionMap_IsRedacted(&map, beginPageNum - 1);
    auto const afterWasSet = OfflineDumpRedactionMap_IsRedacted(&map, endPageNum);
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, beginPageNum, endPageNum));
    TestAssert(beforeWasSet == OfflineDumpRedactionMap_IsRedacted(&map, beginPageNum - 1));
    TestAssert(afterWasSet == OfflineDumpRedactionMap_IsRedacted(&map, endPageNum));

    auto range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum, endPageNum);
    TestAssert(range.BeginRedactedPageNum == beginPageNum);
    TestAssert(range.EndRedactedPageNum == endPageNum);

    if (beginPageNum - 1 < beginPageNum)
    {
        range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum - 1, endPageNum);
        TestAssert(range.BeginRedactedPageNum == beforeWasSet ? beginPageNum - 1 : beginPageNum);
        TestAssert(range.EndRedactedPageNum == endPageNum);
    }

    if (endPageNum < endPageNum + 1)
    {
        range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, beginPageNum, endPageNum + 1);
        TestAssert(range.BeginRedactedPageNum == beginPageNum);
        TestAssert(range.EndRedactedPageNum == afterWasSet ? endPageNum + 1 : endPageNum);
    }

    if (endPageNum - beginPageNum < 256)
    {
        for (UINT64 pageNum = beginPageNum; pageNum != endPageNum; pageNum += 1)
        {
            TestAssert(OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
    }
    else
    {
        for (UINT64 pageNum = beginPageNum; pageNum != beginPageNum + 128; pageNum += 1)
        {
            TestAssert(OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
        for (UINT64 pageNum = endPageNum - 128; pageNum != endPageNum; pageNum += 1)
        {
            TestAssert(OfflineDumpRedactionMap_IsRedacted(&map, pageNum));
        }
    }
}

static void
ValidateMap(OFFLINE_DUMP_REDACTION_MAP const& map, UINT64 const* ranges, unsigned pairs)
{
    OFFLINE_DUMP_REDACTION_MAP_RANGE range;
    UINT64 pos = 0;
    UINT64 const end = pairs ? ranges[pairs * 2 - 1] : 0;
    for (unsigned i = 0; i != pairs * 2; i += 2)
    {
        range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, pos, end);
        TestAssert(range.BeginRedactedPageNum == ranges[i]);
        TestAssert(range.EndRedactedPageNum == ranges[i + 1]);
        pos = range.EndRedactedPageNum;
    }

    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, pos, end + 1);
    TestAssert(range.BeginRedactedPageNum == end + 1);
    TestAssert(range.EndRedactedPageNum == end + 1);
}

template<unsigned N>
static void
ValidateMap(OFFLINE_DUMP_REDACTION_MAP const& map, UINT64 const (&ranges)[N])
{
    static_assert(N % 2 == 0, "ranges must be even");
    ValidateMap(map, ranges, N / 2);
}

static void
InitAndValidateMap(UINT64 const* ranges, unsigned pairs)
{
    OFFLINE_DUMP_REDACTION_MAP map;
    auto const MaxPageNo = MAX_BITS_PER_TABLE0;
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, sizeof(g_mapBuf), MaxPageNo));

    for (unsigned i = 0; i != pairs * 2; i += 2)
    {
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, ranges[i], ranges[i + 1]));
    }

    ValidateMap(map, ranges, pairs);
}

template<unsigned N>
static void
InitAndValidateMap(UINT64 const (&ranges)[N])
{
    static_assert(N % 2 == 0, "ranges must be even");
    InitAndValidateMap(ranges, N / 2);
}

static void
OfflineDumpRedactionMap_GetFirstRedactedRange_Test()
{
    OFFLINE_DUMP_REDACTION_MAP map;
    auto const MaxPageNo = MAX_BITS_PER_TABLE0;

    // Initialize the map with enough space for bitmaps.
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, sizeof(g_mapBuf), MaxPageNo));
    ValidateMap(map, nullptr, 0);

    // Test case: Empty map (no redacted ranges)
    auto range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == MaxPageNo);
    TestAssert(range.EndRedactedPageNum == MaxPageNo);

    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 10, 20));
    ValidateMap(map, { 10, 20 });

    // Test case: Single redacted range
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 20);
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 9, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 20);
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 10, 20);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 20);
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 11, 19);
    TestAssert(range.BeginRedactedPageNum == 11);
    TestAssert(range.EndRedactedPageNum == 19);

    // map = [10..20], [30..70]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 30, 70));
    ValidateMap(map, { 10, 20, 30, 70 });
    // Test case: Multiple redacted ranges
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 20);

    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 20, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == 30);
    TestAssert(range.EndRedactedPageNum == 70);

    // Test case: Query range within a redacted range
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 15, 25);
    TestAssert(range.BeginRedactedPageNum == 15);
    TestAssert(range.EndRedactedPageNum == 20);

    // Test case: Query range partially overlapping a redacted range
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 5, 15);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 15);

    // Test case: Query range after all redacted ranges
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 70, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == MaxPageNo);
    TestAssert(range.EndRedactedPageNum == MaxPageNo);

    // Test case: Query range before all redacted ranges
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, 5);
    TestAssert(range.BeginRedactedPageNum == 5);
    TestAssert(range.EndRedactedPageNum == 5);

    // Test case: Query range exactly matching a redacted range
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 10, 20);
    TestAssert(range.BeginRedactedPageNum == 10);
    TestAssert(range.EndRedactedPageNum == 20);

    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 10, 15));
    ValidateMap(map, { 15, 20, 30, 70 });
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 10, 20));
    ValidateMap(map, { 30, 70 });
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 30, 70));
    ValidateMap(map, nullptr, 0);

    // Test case: Clear all redacted ranges and check again
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == MaxPageNo);
    TestAssert(range.EndRedactedPageNum == MaxPageNo);

    // map = [0..5]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 0, 5));
    ValidateMap(map, { 0, 5 });

    // Test case: Boundary conditions at the start of the map
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 0, 5);
    TestAssert(range.BeginRedactedPageNum == 0);
    TestAssert(range.EndRedactedPageNum == 5);

    // map = [0..5], [Max - 5..Max]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo - 5, MaxPageNo));
    ValidateMap(map, { 0, 5, MaxPageNo - 5, MaxPageNo });

    // Test case: Boundary conditions at the end of the map
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, MaxPageNo - 5, MaxPageNo);
    TestAssert(range.BeginRedactedPageNum == MaxPageNo - 5);
    TestAssert(range.EndRedactedPageNum == MaxPageNo);

    // map = [0..5] [15..25] [Max - 5..Max]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 15, 25));
    ValidateMap(map, { 0, 5, 15, 25, MaxPageNo - 5, MaxPageNo });

    // Test case: Overlapping redacted ranges
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 10, 30);
    TestAssert(range.BeginRedactedPageNum == 15);
    TestAssert(range.EndRedactedPageNum == 25);

    // map = [0..5] [15..25] [Max - 5..Max]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 50, 50));
    ValidateMap(map, { 0, 5, 15, 25, MaxPageNo - 5, MaxPageNo});

    // Test case: 0 page range
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 49, 49);
    TestAssert(range.BeginRedactedPageNum == 49);
    TestAssert(range.EndRedactedPageNum == 49);
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 50, 50);
    TestAssert(range.BeginRedactedPageNum == 50);
    TestAssert(range.EndRedactedPageNum == 50);

    // map = [0..5] [15..25] [Max - 5..Max]
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 60, 70));
    ValidateMap(map, { 0, 5, 15, 25, 60, 70, MaxPageNo - 5, MaxPageNo });
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 80, 90));
    ValidateMap(map, { 0, 5, 15, 25, 60, 70, 80, 90, MaxPageNo - 5, MaxPageNo });

    // Test case: Non-redacted pages in between redacted ranges
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 60, 90);
    TestAssert(range.BeginRedactedPageNum == 60);
    TestAssert(range.EndRedactedPageNum == 70);

    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 70, 90);
    TestAssert(range.BeginRedactedPageNum == 80);
    TestAssert(range.EndRedactedPageNum == 90);

    // Test case: Large ranges
    TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 100, 1000));
    ValidateMap(map, { 0, 5, 15, 25, 60, 70, 80, 90, 100, 1000, MaxPageNo - 5, MaxPageNo });
    range = OfflineDumpRedactionMap_GetFirstRedactedRange(&map, 100, 1000);
    TestAssert(range.BeginRedactedPageNum == 100);
    TestAssert(range.EndRedactedPageNum == 1000);
}

void
OfflineDumpRedactionMap_Mark_Test()
{
    {
        OFFLINE_DUMP_REDACTION_MAP map;
        auto const MaxPageNo = MAX_BITS_PER_TABLE0;

        // Full address space but no room for bitmaps.
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, 64 * 1024, MaxPageNo));

        // Clearing should succeed as long as begin <= end && end <= MaxPageNo.

        // Check begin <= end.
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, 0, 1) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, 1, 1) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, 2, 1) == EFI_INVALID_PARAMETER);

        // Check end <= MaxPageNo.
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo - 1, MaxPageNo - 1) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo - 1, MaxPageNo + 0) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo - 1, MaxPageNo + 1) == EFI_INVALID_PARAMETER);


        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo + 1, MaxPageNo + 1));
        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo, MaxPageNo + 1));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 0, 0));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo, MaxPageNo));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 0, 1));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo - 1, MaxPageNo));

        // Setting should fail because there is no room for bitmaps (unless it's a no-op).

        // Check begin <= end.
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, 0, 1) == EFI_OUT_OF_RESOURCES);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, 1, 1) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, 2, 1) == EFI_INVALID_PARAMETER);

        // Check end <= MaxPageNo.
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo - 1, MaxPageNo - 1) == EFI_SUCCESS);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo - 1, MaxPageNo + 0) == EFI_OUT_OF_RESOURCES);
        TestAssert(OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo - 1, MaxPageNo + 1) == EFI_INVALID_PARAMETER);
    }

    {
        OFFLINE_DUMP_REDACTION_MAP map;
        auto const MaxPageNo = MAX_BITS_PER_TABLE0 / 2;

        // Large but not complete address space. Room for several bitmaps.
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, sizeof(g_mapBuf), MaxPageNo));

        // Clearing should succeed as long as the ending page# is less than MaxPageNo.
        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo + 1, MaxPageNo + 1));
        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo, MaxPageNo + 1));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, 0, 0));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, FALSE, MaxPageNo, MaxPageNo));

        // Setting should succeed because there is room for bitmaps.
        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo + 1, MaxPageNo + 1));
        TestAssert(EFI_INVALID_PARAMETER == OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo, MaxPageNo + 1));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, 0, 0));
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Mark(&map, TRUE, MaxPageNo, MaxPageNo));

        // Within the same bitmap, start of address range.

        SetAndCheck(map, 0, 513);
        ClearAndCheck(map, 0, 1); // Start to middle.
        ClearAndCheck(map, 2, 4); // Middle to middle.
        ClearAndCheck(map, 10, 64); // Middle to end.
        ClearAndCheck(map, 128, 192); // Start to end.
        ClearAndCheck(map, 256, 330); // Start to next middle.
        ClearAndCheck(map, 332, 385); // Middle to next middle.
        ClearAndCheck(map, 400, 512); // Middle to next end.

        ClearAndCheck(map, 0, 513);
        SetAndCheck(map, 0, 1); // Start to middle.
        SetAndCheck(map, 2, 4); // Middle to middle.
        SetAndCheck(map, 10, 64); // Middle to end.
        SetAndCheck(map, 128, 192); // Start to end.
        SetAndCheck(map, 256, 330); // Start to next middle.
        SetAndCheck(map, 332, 385); // Middle to next middle.
        SetAndCheck(map, 400, 512); // Middle to next end.

        // Within the same bitmap, end of address range.

        SetAndCheck(map, MaxPageNo - 16, MaxPageNo);
        ClearAndCheck(map, MaxPageNo - 16, MaxPageNo - 15);
        ClearAndCheck(map, MaxPageNo - 14, MaxPageNo - 12);
        ClearAndCheck(map, MaxPageNo - 11, MaxPageNo - 7);
        ClearAndCheck(map, MaxPageNo - 6, MaxPageNo - 2);

        ClearAndCheck(map, MaxPageNo - 16, MaxPageNo);
        SetAndCheck(map, MaxPageNo - 16, MaxPageNo - 15);
        SetAndCheck(map, MaxPageNo - 14, MaxPageNo - 12);
        SetAndCheck(map, MaxPageNo - 11, MaxPageNo - 7);
        SetAndCheck(map, MaxPageNo - 6, MaxPageNo - 2);

        // Crossing through three real bitmaps.

        // This will cause bitmaps 0, 1, and 2 to be allocated.
        ClearAndCheck(map, BITS_PER_BITMAP - 16, BITS_PER_BITMAP * 2 + 16);   // Clear bits from bitmap[0] to bitmap[2].
        SetAndCheck(map, BITS_PER_BITMAP - 15, BITS_PER_BITMAP * 2 + 15);   // Set bits from bitmap[0] to bitmap[2].

        // Bitmaps 0, 1, and 2 are already allocated.
        SetAndCheck(map, BITS_PER_BITMAP - 16, BITS_PER_BITMAP * 2 + 16);   // Set bits from bitmap[0] to bitmap[2].
        ClearAndCheck(map, BITS_PER_BITMAP - 15, BITS_PER_BITMAP * 2 + 15); // Clear bits from bitmap[0] to bitmap[2].

        // Crossing from real bitmap into fake (zeroed) bitmap and back into real bitmap.

        // Deallocate all bitmaps, then allocate 0 and 2. bitmap[1] remains unallocated.
        TestAssert(EFI_SUCCESS == OfflineDumpRedactionMap_Init(&map, &g_mapBuf, sizeof(g_mapBuf), MaxPageNo));
        SetAndCheck(map, BITS_PER_BITMAP - 16, BITS_PER_BITMAP);              // Allocate bitmap[0], set bits at the end.
        SetAndCheck(map, BITS_PER_BITMAP * 2, BITS_PER_BITMAP * 2 + 16);      // Allocate bitmap[1], set bits at the start.
        ClearAndCheck(map, BITS_PER_BITMAP - 15, BITS_PER_BITMAP * 2 + 15);   // Clear bits from bitmap[0] to bitmap[2].
    }

    InitAndValidateMap({ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    InitAndValidateMap({ 0, 63 });
    InitAndValidateMap({ 0, 64 });
    InitAndValidateMap({ 0, 65 });

    InitAndValidateMap({ 1, 63 });
    InitAndValidateMap({ 63, 64 });
    InitAndValidateMap({ 64, 65 });

    InitAndValidateMap({ 0, 255 });
    InitAndValidateMap({ 0, 256 });
    InitAndValidateMap({ 0, 257 });

    InitAndValidateMap({ 1, 255 });
    InitAndValidateMap({ 63, 256 });
    InitAndValidateMap({ 64, 257 });

    InitAndValidateMap({ BITS_PER_BITMAP - 65, BITS_PER_BITMAP });
    InitAndValidateMap({ BITS_PER_BITMAP - 64, BITS_PER_BITMAP });
    InitAndValidateMap({ BITS_PER_BITMAP - 63, BITS_PER_BITMAP });
    InitAndValidateMap({ BITS_PER_BITMAP - 1,  BITS_PER_BITMAP });

    InitAndValidateMap({ BITS_PER_BITMAP - 65, BITS_PER_BITMAP + 1 });
    InitAndValidateMap({ BITS_PER_BITMAP - 64, BITS_PER_BITMAP + 63 });
    InitAndValidateMap({ BITS_PER_BITMAP - 63, BITS_PER_BITMAP + 64 });
    InitAndValidateMap({ BITS_PER_BITMAP - 1,  BITS_PER_BITMAP + 65 });

    InitAndValidateMap({ BITS_PER_BITMAP - 65, BITS_PER_BITMAP + BITS_PER_BITMAP + 1});
    InitAndValidateMap({ BITS_PER_BITMAP - 64, BITS_PER_BITMAP + BITS_PER_BITMAP + 63 });
    InitAndValidateMap({ BITS_PER_BITMAP - 63, BITS_PER_BITMAP + BITS_PER_BITMAP + 64 });
    InitAndValidateMap({ BITS_PER_BITMAP - 1,  BITS_PER_BITMAP + BITS_PER_BITMAP + 65 });

    InitAndValidateMap({ BITS_PER_TABLE1 - 65, BITS_PER_TABLE1 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 64, BITS_PER_TABLE1 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 63, BITS_PER_TABLE1 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 1,  BITS_PER_TABLE1 });

    InitAndValidateMap({ BITS_PER_TABLE1 - 65, BITS_PER_TABLE1 + BITS_PER_BITMAP + 1 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 64, BITS_PER_TABLE1 + BITS_PER_BITMAP + 63 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 63, BITS_PER_TABLE1 + BITS_PER_BITMAP + 64 });
    InitAndValidateMap({ BITS_PER_TABLE1 - 1,  BITS_PER_TABLE1 + BITS_PER_BITMAP + 65 });
}

void
SparseBitmapTest()
{
    OfflineDumpRedactionMap_Init_Test();
    OfflineDumpRedactionMap_Mark_Test();
    OfflineDumpRedactionMap_GetFirstRedactedRange_Test();
}
