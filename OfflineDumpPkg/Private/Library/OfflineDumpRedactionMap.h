// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Redaction tracking for Offline Dump page bitmap.

Maps PageNum (UINT64) to IsRedacted (BOOLEAN) via sparse bitmap.

*** Assumes ***

- Caller provides/owns the memory.
- Page numbers are limited to 44-bits. Assuming a 4KB page, that provides access to a
  56-bit physical address space.

*** Computing the amount of memory to reserve ***

With the current implementation, the exact memory needed for redaction is
Table0 usage + Table1 usage + Bitmap usage:

- Table0 usage = (Highest used physical address) / 2^40, rounded up to multiple of 4KB.
  For a full 56-bit address space, this is 2^56 / 2^40 = 64KB.
- Table1 usage = (Number of 4TB regions touched in your memory map) * 4KB.
  For a full 56-bit address space, this is 16K * 4KB = 64MB.
- Bitmap usage = (Number of 4GB regions touched in your memory map) * 128KB.
  For a full 56-bit address space, this is 16M * 128KB = 2TB.

If physical addresses are all below 4TB then Table0 will be 4KB, there will be one 4KB
Table1, and we can conservatively assume that every 4GB region needs a 128KB bitmap, so
we can conservatively estimate redaction memory usage as 8KB + (highest physical address,
rounded up to a multiple of 2^32, divided by 2^15) bytes. For example, for a system where
the highest physical address is 129G, you can estimate the memory needed as:

1. Round 129G up to a multiple of 4G to get 132G, which is 132 * 2^30.
2. We'll need: 8KB + (132 * 2^30 / 2^15) bytes.
3. We'll need: 8KB + (132 * 2^30 / 2^15 / 2^10) KB.
4. We'll need: 8KB + (132 * 2^5) KB.
5. We'll need: 8KB + 4224KB = 4232KB.

*** Implementation details ***

PageNum bits are used to perform a lookup as follows:

- 30..43: Root Table0 contains up to 16K (2^14) UINT32 elements = up to 64KB. Each
  element is the ChunkNum of the start of the corresponding Table1, or 0 for NULL.
- 20..29: Each Table1 contains 1K (2^10) UINT32 elements = 4KB. Each element is the
  ChunkNum of the start of the corresponding Bitmap, or 0 for NULL.
- 6..19: Each Bitmap is 16K (2^14) UINT64 entries = 128KB.
- 0..5: Each UINT64 entry contains 64 bits (2^6). Each bit represents a page's redaction.

As described above, a bitmap covering the full 44-bit page space would require a little
more than 2TB. ChunkNum is UINT32. Using 4KB chunks, 2TB / 4KB per chunk = 2^29 chunks.
Maximum ChunkNum will therefore fit in 30 bits.
*/

#ifndef _included_OfflineDumpRedactionMap_h
#define _included_OfflineDumpRedactionMap_h

#include <Uefi/UefiBaseType.h>

// Implementation detail.
struct _offline_dump_redaction_map_CHUNK;

// Redaction map structure. Treat as opaque.
typedef struct {
  UINT64                                      MaxPageNum;       // Page numbers with this value or higher are not redacted.
  struct _offline_dump_redaction_map_CHUNK    *pBufferChunks;   // Table0 starts at pBufferChunks[0].
  UINT32                                      MaxBufferChunks;  // pBufferChunks is OFFLINE_DUMP_REDACTION_MAP_CHUNK[MaxBufferChunks].
  UINT32                                      UsedBufferChunks; // Next unused chunk is pBufferChunks[UsedBufferChunks].
} OFFLINE_DUMP_REDACTION_MAP;

// Returned by OfflineDumpRedactionMap_GetFirstRedactedRange(pMap, BeginPageNum, EndPageNum).
typedef struct {
  UINT64    BeginRedactedPageNum;
  UINT64    EndRedactedPageNum;
} OFFLINE_DUMP_REDACTION_MAP_RANGE;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
Initializes the redaction map.

pMap: Pointer to the redaction map to initialize.
pBuffer: Pointer to the buffer to use for page tracking. Must be UINT64-aligned.
BufferSize: Size of the buffer in bytes.
MaxPageNum: 1 + highest PageNum that could possibly be redacted, e.g. 0x1000000000
            for a 36-bit PageNum (a 48-bit physical address space). This value
            determines the size of the root table (Table0). Pages above this value
            cannot be redacted. This value must not be larger than 2^44 (max 56-bit
            physical address space).
*/
EFI_STATUS
OfflineDumpRedactionMap_Init (
  OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN void                         *pBuffer,
  IN UINTN                        BufferSize,
  IN UINT64                       MaxPageNum
  );

/*
Marks the specified page as exposed (unredacted).

This function is for exposing a single page. Use
OfflineDumpRedactionMap_MarkRange to redact a page or to mark a range of pages.
*/
void
OfflineDumpRedactionMap_ExposePage (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN UINT64                          PageNum
  );

/*
Marks the specified pages as redacted or exposed.

Fails if EndPageNum > OfflineDumpRedactionMapMaxPageNumber(pMap)
or if IsRedacted and map is out of buffer space.
*/
EFI_STATUS
OfflineDumpRedactionMap_MarkRange (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN BOOLEAN                         IsRedacted,
  IN UINT64                          BeginPageNum,
  IN UINT64                          EndPageNum
  );

/*
Returns TRUE if the specified page is redacted, FALSE otherwise.
Any page not covered by the map is considered not redacted.

This function is for testing a single page. Use
OfflineDumpRedactionMap_GetFirstRedactedRange to test a range of pages.
*/
BOOLEAN
OfflineDumpRedactionMap_IsRedacted (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN UINT64                            PageNum
  );

/*
Finds the first redacted range in the specified page range.

Requires: BeginPageNum <= EndPageNum.

Returns: { BeginRedactedPageNum, EndRedactedPageNum }.

Partitions the provided page range BeginPageNum..EndPageNum into three ranges:

- BeginPageNum..BeginRedactedPageNum is exposed (may be written to the dump).
- BeginRedactedPageNum..EndRedactedPageNum is redacted (must be omitted, zeroed,
  or encrypted).
- EndRedactedPageNum..EndPageNum remains unprocessed (call
  OfflineDumpRedactionMap_GetFirstRedactedRange again if this range is not empty).
*/
OFFLINE_DUMP_REDACTION_MAP_RANGE
OfflineDumpRedactionMap_GetFirstRedactedRange (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap,
  IN UINT64                            BeginPageNum,
  IN UINT64                            EndPageNum
  );

/*
Returns the value of MaxPageNum that was passed to OfflineDumpRedactionMapInit, or 0
if OfflineDumpRedactionMapInit failed.
*/
UINT64
OfflineDumpRedactionMap_MaxPageNumber (
  IN OFFLINE_DUMP_REDACTION_MAP const  *pMap
  );

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // _included_OfflineDumpRedactionMap_h
