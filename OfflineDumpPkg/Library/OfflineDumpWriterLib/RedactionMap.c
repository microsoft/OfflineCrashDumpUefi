// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <Library/OfflineDumpRedactionMapInternal.h>
#include <Library/OfflineDumpRedactionMap.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

typedef struct _offline_dump_redaction_map_CHUNK {
  CHUNK_NUM    Data[BYTES_PER_CHUNK / sizeof (CHUNK_NUM)];
} CHUNK;
STATIC_ASSERT (
               sizeof (CHUNK) == BYTES_PER_CHUNK,
               "sizeof(CHUNK) must be BYTES_PER_CHUNK"
               );
STATIC_ASSERT (
               sizeof (CHUNK) == TABLE0_CHUNK_SIZE,
               "sizeof(CHUNK) must be TABLE0_CHUNK_SIZE"
               );
STATIC_ASSERT (
               TABLE0_CHUNK_SIZE == TABLE1_PER_TABLE0_CHUNK * sizeof (CHUNK_NUM),
               "TABLE0_CHUNK_SIZE must be TABLE1_PER_TABLE0_CHUNK * sizeof(CHUNK_NUM)"
               );

typedef struct {
  CHUNK_NUM    BitmapChunkNum[BITMAPS_PER_TABLE1];
} TABLE1;
STATIC_ASSERT (
               sizeof (TABLE1) % sizeof (CHUNK) == 0,
               "sizeof(TABLE1) must be a multiple of sizeof(CHUNK)"
               );
STATIC_ASSERT (
               sizeof (TABLE1) == TABLE1_SIZE,
               "sizeof(TABLE1) must equal TABLE1_SIZE"
               );

typedef UINT64 ENTRY;
STATIC_ASSERT (
               sizeof (ENTRY) * 8 == BITS_PER_ENTRY,
               "sizeof(ENTRY) must align with BITS_PER_ENTRY"
               );

typedef struct {
  ENTRY    Entry[ENTRIES_PER_BITMAP]; // Indexed by BitmapIndex
} BITMAP;
STATIC_ASSERT (
               sizeof (BITMAP) % sizeof (CHUNK) == 0,
               "sizeof(BITMAP) must be a multiple of sizeof(CHUNK)"
               );
STATIC_ASSERT (
               sizeof (BITMAP) == BITMAP_SIZE,
               "sizeof(BITMAP) must equal BITMAP_SIZE"
               );

#define CHUNKS_PER_TABLE1  (sizeof(TABLE1) / sizeof(CHUNK))
#define CHUNKS_PER_BITMAP  (sizeof(BITMAP) / sizeof(CHUNK))

// Implements BitScanForward64:
// If Value == 0, returns FALSE.
// If Value != 0, returns TRUE and sets *pTrailingZeros to the number of trailing zero bits in Value.
static BOOLEAN
CountTrailingZeros64 (
  IN UINT64  Value,
  OUT UINT8  *pTrailingZeros
  )
{
 #ifdef _MSC_VER
  unsigned long  TrailingZeros = 0;
  if (_BitScanForward64 (&TrailingZeros, Value)) {
    *pTrailingZeros = (UINT8)TrailingZeros;
    return TRUE;
  } else {
    return FALSE;
  }

 #else
  if (Value == 0) {
    return FALSE;
  } else {
    *pTrailingZeros = (UINT8)__builtin_ctzll (Value);
    return TRUE;
  }

 #endif
}

// Use result as index into Table0 to get Table1ChunkNum.
// Precondition: PageNum < 2^44
static UINT32
PageNumToToTable0Index (
  IN UINT64  PageNum
  )
{
  ASSERT (PageNum < MAX_BITS_PER_TABLE0);  // Data corruption
  return (UINT32)(PageNum >> BITS_PER_TABLE1_SHIFT) & (MAX_TABLE1S_PER_TABLE0 - 1);
}

// Use result as index into Table1 to get BitmapChunkNum.
static UINT32
PageNumToTable1Index (
  IN UINT64  PageNum
  )
{
  return (UINT32)(PageNum >> BITS_PER_BITMAP_SHIFT) & (BITMAPS_PER_TABLE1 - 1);
}

// Use result as index into Bitmap to get Entry.
static UINT32
PageNumToBitmapIndex (
  IN UINT64  PageNum
  )
{
  return (UINT32)(PageNum >> BITS_PER_ENTRY_SHIFT) & (ENTRIES_PER_BITMAP - 1);
}

// Use result as index into Entry to get Bit, i.e.
// Bit = (Entry >> EntryShift) & 1.
static UINT8
PageNumToEntryShift (
  IN UINT64  PageNum
  )
{
  return (UINT8)(PageNum & (BITS_PER_ENTRY - 1));
}

// Returns pointer to Table0[PageNum.Table0Index].
// Precondition: PageNum < pMap->MaxPageNum
static CHUNK_NUM *
PageNumToTable1ChunkNumPtr (
  IN OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN UINT64                      PageNum
  )
{
  ASSERT (pMap->MaxPageNum <= MAX_BITS_PER_TABLE0); // Data corruption
  ASSERT (PageNum < pMap->MaxPageNum);              // Precondition
  CHUNK_NUM  *pTable0 = pMap->pBufferChunks[0].Data;
  return &pTable0[PageNumToToTable0Index (PageNum)];
}

// Returns Table0[PageNum.Table0Index].
// Precondition: PageNum < pMap->MaxPageNum
static CHUNK_NUM
PageNumToTable1ChunkNum (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN UINT64                            PageNum
  )
{
  return *PageNumToTable1ChunkNumPtr ((OFFLINE_DUMP_REDACTION_MAP *)pMap, PageNum);
}

// Returns (TABLE1*)&pBufferChunks[ChunkNum]
// Precondition: ChunkNum < pMap->MaxBufferChunks
static TABLE1 *
GetChunkAsTable1 (
  IN OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN CHUNK_NUM                   ChunkNum
  )
{
  ASSERT (ChunkNum + (CHUNK_NUM)(sizeof (TABLE1) / sizeof (CHUNK)) > ChunkNum);
  ASSERT (ChunkNum + (CHUNK_NUM)(sizeof (TABLE1) / sizeof (CHUNK)) <= pMap->MaxBufferChunks);
  return (TABLE1 *)&pMap->pBufferChunks[ChunkNum];
}

// Returns (TABLE1*)&pBufferChunks[ChunkNum]
// Precondition: ChunkNum < pMap->MaxBufferChunks
static TABLE1 const *
GetChunkAsTable1Const (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN CHUNK_NUM                         ChunkNum
  )
{
  return GetChunkAsTable1 ((OFFLINE_DUMP_REDACTION_MAP *)pMap, ChunkNum);
}

// Returns pointer to Table1[PageNum.Table1Index]
static CHUNK_NUM *
PageNumToBitmapChunkNumPtr (
  IN TABLE1  *pTable1,
  IN UINT64  PageNum
  )
{
  return &pTable1->BitmapChunkNum[PageNumToTable1Index (PageNum)];
}

// Returns Table1[PageNum.Table1Index]
static CHUNK_NUM
PageNumToBitmapChunkNum (
  IN TABLE1 const  *pTable1,
  IN UINT64        PageNum
  )
{
  return pTable1->BitmapChunkNum[PageNumToTable1Index (PageNum)];
}

// Returns (BITMAP*)&pBufferChunks[ChunkNum]
// Precondition: ChunkNum < pMap->MaxBufferChunks
static BITMAP *
GetChunkAsBitmap (
  IN OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN CHUNK_NUM                   ChunkNum
  )
{
  ASSERT (ChunkNum + (CHUNK_NUM)(sizeof (BITMAP) / sizeof (CHUNK)) > ChunkNum);
  ASSERT (ChunkNum + (CHUNK_NUM)(sizeof (BITMAP) / sizeof (CHUNK)) <= pMap->MaxBufferChunks);
  return (BITMAP *)&pMap->pBufferChunks[ChunkNum];
}

// Returns (BITMAP*)&pBufferChunks[ChunkNum]
// Precondition: ChunkNum < pMap->MaxBufferChunks
static BITMAP const *
GetChunkAsBitmapConst (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN CHUNK_NUM                         ChunkNum
  )
{
  return GetChunkAsBitmap ((OFFLINE_DUMP_REDACTION_MAP *)pMap, ChunkNum);
}

static void
AssertMapValid (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap
  )
{
  ASSERT (pMap->MaxPageNum <= MAX_BITS_PER_TABLE0);
  ASSERT (0 == (UINTN)pMap->pBufferChunks % sizeof (ENTRY));
  ASSERT (pMap->MaxBufferChunks < 0x80000000);
  ASSERT (pMap->UsedBufferChunks <= pMap->MaxBufferChunks);

  if (pMap->MaxPageNum != 0) {
    ASSERT (pMap->pBufferChunks != NULL);
    ASSERT (pMap->UsedBufferChunks != 0);    // Expect TABLE0.
  }
}

EFI_STATUS
OfflineDumpRedactionMap_Init (
  OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN void                         *pBuffer,
  IN UINTN                        BufferSize,
  IN UINT64                       MaxPageNum
  )
{
  UINT32 const  MaxBufferChunks =
    (BufferSize / sizeof (CHUNK)) >= ~(UINT32)0
        ? ~(UINT32)0
        : (UINT32)(BufferSize / sizeof (CHUNK));

  pMap->MaxPageNum       = 0; // If an error occurs, the resulting bitmap redacts nothing.
  pMap->pBufferChunks    = NULL;
  pMap->MaxBufferChunks  = 0;
  pMap->UsedBufferChunks = 0;   // If an error occurs, the resulting bitmap's buffer is full.

  EFI_STATUS  Status;
  if (MaxPageNum > MAX_BITS_PER_TABLE0) {
    // We can't handle page numbers 2^44 or larger.
    Status = EFI_INVALID_PARAMETER;
  } else {
    #define TABLE0ITEMS_FROM_PAGENUMBERMAX(MaxPageNum) \
        (UINT32)DIVIDE_AND_ROUND_UP(MaxPageNum, BITS_PER_TABLE1)

    // Compute the number of items needed in Table0 to reach up to MaxPageNum.
    STATIC_ASSERT (
                   0 == TABLE0ITEMS_FROM_PAGENUMBERMAX (0),
                   "Incorrect computation for Table0Items(0)"
                   );
    STATIC_ASSERT (
                   1 == TABLE0ITEMS_FROM_PAGENUMBERMAX (1),
                   "Incorrect computation for Table0Items(1)"
                   );
    STATIC_ASSERT (
                   MAX_TABLE1S_PER_TABLE0 == TABLE0ITEMS_FROM_PAGENUMBERMAX (MAX_BITS_PER_TABLE0),
                   "Incorrect computation for Table0Items(max)"
                   );
    UINT32 const  Table0Items  = TABLE0ITEMS_FROM_PAGENUMBERMAX (MaxPageNum);
    UINT32 const  Table0Bytes  = Table0Items * sizeof (CHUNK_NUM);
    UINT32 const  Table0Chunks = DIVIDE_AND_ROUND_UP (Table0Bytes, BYTES_PER_CHUNK);
    if (Table0Chunks > MaxBufferChunks) {
      Status = EFI_OUT_OF_RESOURCES;
    } else {
      // Success: redact up to MaxPageNum, bitmap contains empty Table0.
      ZeroMem (pBuffer, Table0Chunks * sizeof (CHUNK));
      pMap->MaxPageNum       = MaxPageNum;
      pMap->pBufferChunks    = (CHUNK *)pBuffer;
      pMap->MaxBufferChunks  = MaxBufferChunks;
      pMap->UsedBufferChunks = Table0Chunks;
      Status                 = EFI_SUCCESS;
    }
  }

  AssertMapValid (pMap);
  return Status;
}

EFI_STATUS
OfflineDumpRedactionMap_MarkRange (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN BOOLEAN                         IsRedacted,
  IN UINT64                          BeginPageNum,
  IN UINT64                          EndPageNum
  )
{
  AssertMapValid (pMap);

  if ((EndPageNum < BeginPageNum) || (EndPageNum > pMap->MaxPageNum)) {
    return EFI_INVALID_PARAMETER;
  }

  UINT64  PageNum = BeginPageNum;
  while (PageNum < EndPageNum) {
    // Each iteration of this loop will make changes to at most one BITMAP.
    //
    // 1. Find the bitmap that contains PageNum.
    //    - If IsRedacted and the bitmap is NULL, we allocate a new BITMAP.
    //    - If !IsRedacted and the bitmap is NULL, increment PageNum and loop.
    // 2. Update that bitmap as appropriate.
    // 3. If changes extend beyond the end of the current iteration's BITMAP,
    //    increment PageNum and loop.

    UINT64 const  NextBitmapPageNum =
      ((PageNum >> BITS_PER_BITMAP_SHIFT) + 1) << BITS_PER_BITMAP_SHIFT;

    CHUNK_NUM  BitmapChunkNum;
    if (IsRedacted) {
      CHUNK_NUM  Table1ChunkNum;

      // When redacting, we allocate new TABLE1/BITMAP if not already allocated.

      CHUNK_NUM * const  pTable1ChunkNum = PageNumToTable1ChunkNumPtr (pMap, PageNum);
      Table1ChunkNum = *pTable1ChunkNum;
      if (Table1ChunkNum == 0) {
        if (pMap->MaxBufferChunks < pMap->UsedBufferChunks + CHUNKS_PER_TABLE1) {
          return EFI_OUT_OF_RESOURCES;
        }

        Table1ChunkNum          = pMap->UsedBufferChunks;
        *pTable1ChunkNum        = Table1ChunkNum;
        pMap->UsedBufferChunks += CHUNKS_PER_TABLE1;

        TABLE1 * const  pTable1 = GetChunkAsTable1 (pMap, Table1ChunkNum);
        ZeroMem (pTable1, sizeof (*pTable1));
      }

      CHUNK_NUM * const  pBitmapChunkNum = PageNumToBitmapChunkNumPtr (GetChunkAsTable1 (pMap, Table1ChunkNum), PageNum);
      BitmapChunkNum = *pBitmapChunkNum;
      if (BitmapChunkNum == 0) {
        if (pMap->MaxBufferChunks < pMap->UsedBufferChunks + CHUNKS_PER_BITMAP) {
          return EFI_OUT_OF_RESOURCES;
        }

        BitmapChunkNum          = pMap->UsedBufferChunks;
        *pBitmapChunkNum        = BitmapChunkNum;
        pMap->UsedBufferChunks += CHUNKS_PER_BITMAP;

        BITMAP * const  pBitmap = GetChunkAsBitmap (pMap, BitmapChunkNum);
        ZeroMem (pBitmap, sizeof (*pBitmap));
      }
    } else {
      // When unredacting, we don't need to allocate any new TABLE1 or BITMAP. If the
      // TABLE1 or BITMAP is not already allocated then there are no redacted pages
      // in the corresponding address range and we can just skip it.

      CHUNK_NUM const  Table1ChunkNum = PageNumToTable1ChunkNum (pMap, PageNum);
      if (Table1ChunkNum == 0) {
        // No redacted pages in this Table1's range. Skip to next Table1's range.
        UINT64 const  NextTable1PageNum = ((PageNum >> BITS_PER_TABLE1_SHIFT) + 1) << BITS_PER_TABLE1_SHIFT;
        PageNum = NextTable1PageNum;         // May be greater than EndPageNum.
        continue;
      }

      BitmapChunkNum = PageNumToBitmapChunkNum (GetChunkAsTable1 (pMap, Table1ChunkNum), PageNum);
      if (BitmapChunkNum == 0) {
        // No redacted pages in this Bitmap's range. Skip to next Bitmap's range.
        PageNum = NextBitmapPageNum;         // May be greater than EndPageNum.
        continue;
      }
    }

    BITMAP * const  pBitmap          = GetChunkAsBitmap (pMap, BitmapChunkNum);
    UINT64 const    BitmapEndPageNum = MIN (EndPageNum, NextBitmapPageNum);

    // Leading partial entry?
    UINT8 const  HeadEntryShift = PageNumToEntryShift (PageNum);
    if (HeadEntryShift != 0) {
      // HeadBitCount is MIN(bits after HeadEntryShift, pages yet to be marked).
      UINT8 const  HeadBitCount = (UINT8)MIN (BITS_PER_ENTRY - HeadEntryShift, BitmapEndPageNum - PageNum);

      // Mask bits are:
      // - 0s for bits [0..HeadEntryShift)
      // - 1s for bits [HeadEntryShift..HeadEntryShift + HeadBitCount)
      // - 0s for bits [HeadEntryShift + HeadBitCount..BITS_PER_ENTRY)
      ENTRY const  Mask = ~(ENTRY)0                          // Start with all-1s.
                          >> (BITS_PER_ENTRY - HeadBitCount) // Shift right to give HeadBitCount 1s at bottom.
                          << HeadEntryShift;                 // Shift left to give HeadBitCount 1s in the middle.

      ENTRY * const  pBitmapEntry = &pBitmap->Entry[PageNumToBitmapIndex (PageNum)];
      if (IsRedacted) {
        *pBitmapEntry |= Mask;
      } else {
        *pBitmapEntry &= ~Mask;
      }

      PageNum += HeadBitCount;

      if (PageNum >= BitmapEndPageNum) {
        ASSERT (PageNum == BitmapEndPageNum);
        continue;
      }
    }

    ASSERT (PageNum <= BitmapEndPageNum);
    ASSERT (0 == PageNumToEntryShift (PageNum));

    // Full entries?
    {
      UINT32 const  FullEntryCount = (UINT32)(BitmapEndPageNum - PageNum) >> BITS_PER_ENTRY_SHIFT;
      ENTRY const   FullEntryMask  = IsRedacted ? ~(ENTRY)0 : (ENTRY)0;
      UINT32        BitmapIndex    = PageNumToBitmapIndex (PageNum);
      UINT32 const  BitmapEndIndex = BitmapIndex + FullEntryCount;
      for ( ; BitmapIndex != BitmapEndIndex; BitmapIndex += 1) {
        pBitmap->Entry[BitmapIndex] = FullEntryMask;
      }

      PageNum += (UINT64)FullEntryCount << BITS_PER_ENTRY_SHIFT;
    }

    ASSERT (PageNum <= BitmapEndPageNum);
    ASSERT (0 == PageNumToEntryShift (PageNum));

    // Trailing partial entry?
    UINT8 const  TailBitCount = (UINT8)(BitmapEndPageNum - PageNum) & (BITS_PER_ENTRY - 1);
    if (TailBitCount != 0) {
      ENTRY const  Mask = ~(ENTRY)0         // Start with all-1s.
                          << TailBitCount;  // Shift left to give TailBitCount 0s at bottom.

      ENTRY * const  pBitmapEntry = &pBitmap->Entry[PageNumToBitmapIndex (PageNum)];
      if (IsRedacted) {
        *pBitmapEntry |= ~Mask;
      } else {
        *pBitmapEntry &= Mask;
      }

      PageNum += TailBitCount;

      ASSERT (PageNum == EndPageNum);
      ASSERT (PageNum == BitmapEndPageNum);
      break;
    }
  }

  return EFI_SUCCESS;
}

void
OfflineDumpRedactionMap_ExposePage (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN UINT64                          PageNum
  )
{
  if (PageNum >= pMap->MaxPageNum) {
    return; // PageNum is beyond max (not redacted).
  }

  CHUNK_NUM const  Table1ChunkNum = PageNumToTable1ChunkNum (pMap, PageNum);
  if (Table1ChunkNum == 0) {
    return; // No redacted pages in this Table1's range.
  }

  CHUNK_NUM const  BitmapChunkNum = PageNumToBitmapChunkNum (
                                                             GetChunkAsTable1Const (pMap, Table1ChunkNum),
                                                             PageNum
                                                             );
  if (BitmapChunkNum == 0) {
    return; // No redacted pages in this Bitmap's range.
  }

  BITMAP * const  pBitmap    = GetChunkAsBitmap (pMap, BitmapChunkNum);
  ENTRY * const   pEntry     = &pBitmap->Entry[PageNumToBitmapIndex (PageNum)];
  UINT8 const     EntryShift = PageNumToEntryShift (PageNum);

  *pEntry &= ~((ENTRY)1 << EntryShift);      // Clear the bit.
}

BOOLEAN
OfflineDumpRedactionMap_IsRedacted (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN UINT64                            PageNum
  )
{
  if (PageNum >= pMap->MaxPageNum) {
    return FALSE;
  }

  CHUNK_NUM const  Table1ChunkNum = PageNumToTable1ChunkNum (pMap, PageNum);
  if (Table1ChunkNum == 0) {
    return FALSE;
  }

  CHUNK_NUM const  BitmapChunkNum = PageNumToBitmapChunkNum (
                                                             GetChunkAsTable1Const (pMap, Table1ChunkNum),
                                                             PageNum
                                                             );
  if (BitmapChunkNum == 0) {
    return FALSE;
  }

  BITMAP const * const  pBitmap    = GetChunkAsBitmapConst (pMap, BitmapChunkNum);
  ENTRY const           Entry      = pBitmap->Entry[PageNumToBitmapIndex (PageNum)];
  UINT8 const           EntryShift = PageNumToEntryShift (PageNum);
  return ((Entry >> EntryShift) & 1) != 0;
}

OFFLINE_DUMP_REDACTION_MAP_RANGE
OfflineDumpRedactionMap_GetFirstRedactedRange (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN UINT64                            BeginPageNum,
  IN UINT64                            EndPageNum
  )
{
  OFFLINE_DUMP_REDACTION_MAP_RANGE  Result;

  AssertMapValid (pMap);
  ASSERT (BeginPageNum <= EndPageNum);

  UINT64 const  ClampedEndPageNum    = MIN (EndPageNum, pMap->MaxPageNum);
  UINT64        BeginRedactedPageNum = EndPageNum;
  BOOLEAN       IsRedacted           = FALSE;

  UINT64  PageNum = BeginPageNum;
  for ( ;;) {
    if (PageNum >= ClampedEndPageNum) {
      // If !IsRedacted: we didn't find any redacted pages, BeginRedactedPageNum == EndPageNum.
      // If IsRedacted: we didn't find any unredacted pages after BeginRedactedPageNum.
      Result.BeginRedactedPageNum = BeginRedactedPageNum;
      Result.EndRedactedPageNum   = EndPageNum;
      goto Done;
    }

    // Each iteration of this loop will scan at most one BITMAP.
    //
    // 1. Find the bitmap that contains PageNum.
    //    - If !IsRedacted and the bitmap is NULL, skip to next bitmap (restart loop).
    //    - If IsRedacted and the bitmap is NULL, stop (found 0 after finding 1).
    // 2. Scan for target within this bitmap.
    //    - If not found, skip to next bitmap (restart loop).

    UINT64 const  NextBitmapPageNum =
      ((PageNum >> BITS_PER_BITMAP_SHIFT) + 1) << BITS_PER_BITMAP_SHIFT;

    // When scanning, we don't need to allocate a new TABLE1 or BITMAP. If the
    // TABLE1 or BITMAP is not already allocated then there are no redacted pages
    // in the corresponding address range and we can just skip it.

    CHUNK_NUM const  Table1ChunkNum = PageNumToTable1ChunkNum (pMap, PageNum);
    if (Table1ChunkNum == 0) {
      // NULL table is considered as full of 0s.

      if (IsRedacted) {
        // Scanning for 0 and found it. We're done.
        Result.BeginRedactedPageNum = BeginRedactedPageNum;
        Result.EndRedactedPageNum   = PageNum;
        goto Done;
      }

      // Skip to next Table1's range.
      UINT64 const  NextTable1PageNum = ((PageNum >> BITS_PER_TABLE1_SHIFT) + 1) << BITS_PER_TABLE1_SHIFT;
      PageNum = NextTable1PageNum;       // May be greater than ClampedEndPageNum.
      continue;
    }

    CHUNK_NUM const  BitmapChunkNum = PageNumToBitmapChunkNum (
                                                               GetChunkAsTable1Const (pMap, Table1ChunkNum),
                                                               PageNum
                                                               );
    if (BitmapChunkNum == 0) {
      // NULL bitmap is considered as full of 0s.

      if (IsRedacted) {
        // Scanning for 0 and found it. We're done.
        Result.BeginRedactedPageNum = BeginRedactedPageNum;
        Result.EndRedactedPageNum   = PageNum;
        goto Done;
      }

      // Skip to next Bitmap's range.
      PageNum = NextBitmapPageNum;       // May be greater than ClampedEndPageNum.
      continue;
    }

    static ENTRY const    AllBitsClear     = (ENTRY)0;
    static ENTRY const    AllBitsSet       = ~(ENTRY)0;
    BITMAP const * const  pBitmap          = GetChunkAsBitmapConst (pMap, BitmapChunkNum);
    UINT64 const          BitmapEndPageNum = MIN (ClampedEndPageNum, NextBitmapPageNum);

IsRedactedSet:;

    // If scanning for 0, invert the bits before counting zeros.
    // If scanning for 1, don't invert before counting zeros.
    ENTRY const  AllBitsSetIfRedacted = IsRedacted ? AllBitsSet : AllBitsClear;

    // Leading partial entry?
    UINT8 const  HeadEntryShift = PageNumToEntryShift (PageNum);
    if (HeadEntryShift != 0) {
      UINT8 const  HeadBitCount = (UINT8)MIN (BITS_PER_ENTRY - HeadEntryShift, BitmapEndPageNum - PageNum);
      ENTRY const  ShiftedEntry = (pBitmap->Entry[PageNumToBitmapIndex (PageNum)] ^ AllBitsSetIfRedacted) >> HeadEntryShift;
      UINT8        TrailingZeros;
      if (CountTrailingZeros64 (ShiftedEntry, &TrailingZeros) &&
          (TrailingZeros < HeadBitCount))
      {
        PageNum += TrailingZeros;

        if (IsRedacted) {
          // Scanning for 0 and found it. We're done.
          Result.BeginRedactedPageNum = BeginRedactedPageNum;
          Result.EndRedactedPageNum   = PageNum;
          goto Done;
        }

        // Scanning for 1 and found it. Change modes to scan for 0.
        BeginRedactedPageNum = PageNum;
        IsRedacted           = TRUE;
        goto IsRedactedSet;
      }

      PageNum += HeadBitCount;

      if (PageNum >= BitmapEndPageNum) {
        ASSERT (PageNum == BitmapEndPageNum);
        continue;
      }
    }

    ASSERT (PageNum <= BitmapEndPageNum);
    ASSERT (0 == PageNumToEntryShift (PageNum));

    // Full entries.
    {
      UINT32 const  FullEntryCount = (UINT32)(BitmapEndPageNum - PageNum) >> BITS_PER_ENTRY_SHIFT;
      UINT32 const  BitmapIndex    = PageNumToBitmapIndex (PageNum);
      for (UINT32 FullEntryIndex = 0; FullEntryIndex != FullEntryCount; FullEntryIndex += 1) {
        ENTRY const  Entry = pBitmap->Entry[BitmapIndex + FullEntryIndex] ^ AllBitsSetIfRedacted;
        UINT8        TrailingZeros;
        if (CountTrailingZeros64 (Entry, &TrailingZeros)) {
          PageNum += (UINT64)FullEntryIndex << BITS_PER_ENTRY_SHIFT;
          PageNum += TrailingZeros;
          ASSERT (PageNum <= BitmapEndPageNum);

          if (IsRedacted) {
            // Scanning for 0 and found it. We're done.
            Result.BeginRedactedPageNum = BeginRedactedPageNum;
            Result.EndRedactedPageNum   = PageNum;
            goto Done;
          }

          // Scanning for 1 and found it. Change modes to scan for 0.
          BeginRedactedPageNum = PageNum;
          IsRedacted           = TRUE;
          goto IsRedactedSet;
        }
      }

      PageNum += (UINT64)FullEntryCount << BITS_PER_ENTRY_SHIFT;
    }

    ASSERT (PageNum <= BitmapEndPageNum);
    ASSERT (0 == PageNumToEntryShift (PageNum));

    // Trailing partial entry?
    UINT8 const  TailBitCount = (UINT8)(BitmapEndPageNum - PageNum) & (BITS_PER_ENTRY - 1);
    if (TailBitCount != 0) {
      ENTRY const  Mask = ~(ENTRY)0         // Start with all-1s.
                          << TailBitCount;  // Shift left to give TailBitCount 0s at bottom.
      ENTRY const  MaskedEntry = (pBitmap->Entry[PageNumToBitmapIndex (PageNum)] ^ AllBitsSetIfRedacted) & ~Mask;
      UINT8        TrailingZeros;
      if (CountTrailingZeros64 (MaskedEntry, &TrailingZeros) &&
          (TrailingZeros < TailBitCount))
      {
        PageNum += TrailingZeros;

        if (IsRedacted) {
          // Scanning for 0 and found it. We're done.
          Result.BeginRedactedPageNum = BeginRedactedPageNum;
          Result.EndRedactedPageNum   = PageNum;
          goto Done;
        }

        // Scanning for 1 and found it. Continue scanning for 0.
        BeginRedactedPageNum = PageNum;
        IsRedacted           = TRUE;

        ENTRY const  RemainingEntry         = ~(MaskedEntry >> TrailingZeros);
        UINT8        RemainingTrailingZeros = 0;
        ASSERT (RemainingEntry != 0);        // Bit [TailBitCount - TrailingZeros] is 1.
        CountTrailingZeros64 (RemainingEntry, &RemainingTrailingZeros);
        PageNum += RemainingTrailingZeros;

        ASSERT (PageNum <= EndPageNum);
        ASSERT (PageNum <= BitmapEndPageNum);

        Result.BeginRedactedPageNum = BeginRedactedPageNum;
        Result.EndRedactedPageNum   = PageNum;
        goto Done;
      }

      PageNum += TailBitCount;

      ASSERT (PageNum == EndPageNum);
      ASSERT (PageNum == BitmapEndPageNum);

      Result.BeginRedactedPageNum = BeginRedactedPageNum;
      Result.EndRedactedPageNum   = EndPageNum;
      goto Done;
    }
  }

Done:

  return Result;
}

UINT64
OfflineDumpRedactionMap_MaxPageNumber (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap
  )
{
  ASSERT (pMap->MaxPageNum <= MAX_BITS_PER_TABLE0);
  return pMap->MaxPageNum;
}
