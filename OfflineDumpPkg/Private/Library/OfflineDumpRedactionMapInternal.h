// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Internal details of OfflineDumpRedactionMap.

For use by tests and tools.
*/

#ifndef _included_OfflineDumpRedactionMapInternal_h
#define _included_OfflineDumpRedactionMapInternal_h

#include "OfflineDumpRedactionMap.h"

// Each ENTRY contains 2^6 == 64 bits, covering 2^18 == 256KB.
#define BITS_PER_ENTRY_SHIFT         6u
// Each ENTRY contains 2^6 == 64 bits, covering 2^18 == 256KB.
#define BITS_PER_ENTRY               (1u << BITS_PER_ENTRY_SHIFT)

// Each BITMAP contains 2^14 == 16K ENTRYs, covering 2^32 == 4GB.
#define ENTRIES_PER_BITMAP_SHIFT     14u
// Each BITMAP contains 2^14 == 16K ENTRYs, covering 2^32 == 4GB.
#define ENTRIES_PER_BITMAP           (1u << ENTRIES_PER_BITMAP_SHIFT)

// Each BITMAP contains 2^20 = 1M bits, covering 2^32 == 4GB.
#define BITS_PER_BITMAP_SHIFT        (BITS_PER_ENTRY_SHIFT + ENTRIES_PER_BITMAP_SHIFT)
// Each BITMAP contains 2^20 = 1M bits, covering 2^32 == 4GB.
#define BITS_PER_BITMAP              (1u << BITS_PER_BITMAP_SHIFT)

// Each TABLE1 contains 2^10 == 1K BITMAP INDEXs, covering 2^42 == 4TB.
#define BITMAPS_PER_TABLE1_SHIFT     10u
// Each TABLE1 contains 2^10 == 1K BITMAP INDEXs, covering 2^42 == 4TB.
#define BITMAPS_PER_TABLE1           (1u << BITMAPS_PER_TABLE1_SHIFT)

// Each TABLE1 contains 2^30 = 1G bits, covering 2^42 = 4TB.
#define BITS_PER_TABLE1_SHIFT        (BITS_PER_BITMAP_SHIFT + BITMAPS_PER_TABLE1_SHIFT)
// Each TABLE1 contains 2^30 = 1G bits, covering 2^42 = 4TB.
#define BITS_PER_TABLE1              (1u << BITS_PER_TABLE1_SHIFT)

// Each TABLE0 chunk contains 2^10 = 1K TABLE1s, covering 2^52 == 4PB.
#define TABLE1_PER_TABLE0_CHUNK_SHIFT 10u
// Each TABLE0 chunk contains 2^10 = 1K TABLE1s, covering 2^52 == 4PB.
#define TABLE1_PER_TABLE0_CHUNK       (1u << TABLE1_PER_TABLE0_CHUNK_SHIFT)

// Each TABLE0 chunk contains 2^40 = 1T bits, covering 2^52 == 4PB.
#define BITS_PER_TABLE0_CHUNK_SHIFT (BITS_PER_TABLE1_SHIFT + TABLE1_PER_TABLE0_CHUNK_SHIFT)
// Each TABLE0 chunk contains 2^40 = 1T bits, covering 2^52 == 4PB.
#define BITS_PER_TABLE0_CHUNK       (1ull << BITS_PER_TABLE0_CHUNK_SHIFT)

// Each TABLE0 contains up to 2^14 == 16K TABLE1 INDEXs, covering 2^56 bytes.
#define MAX_TABLE1S_PER_TABLE0_SHIFT 14u
// Each TABLE0 contains up to 2^14 == 16K TABLE1 INDEXs, covering 2^56 bytes.
#define MAX_TABLE1S_PER_TABLE0       (1u << MAX_TABLE1S_PER_TABLE0_SHIFT)

// Each TABLE0 contains up to 2^44 bits, covering 2^56 bytes.
#define MAX_BITS_PER_TABLE0_SHIFT    (BITS_PER_TABLE1_SHIFT + MAX_TABLE1S_PER_TABLE0_SHIFT)
// Each TABLE0 contains up to 2^44 bits, covering 2^56 bytes.
#define MAX_BITS_PER_TABLE0          (1ull << MAX_BITS_PER_TABLE0_SHIFT)

// Each TABLE0 chunk is 4KB.
#define TABLE0_CHUNK_SIZE            4096u
// Each TABLE1 is 4KB.
#define TABLE1_SIZE                  4096u
// Each BITMAP is 128KB.
#define BITMAP_SIZE                 (128u * 1024u)

// (Value + DivisorMacro - 1) >> DivisorMacro_SHIFT
#define DIVIDE_AND_ROUND_UP(Value, DivisorMacro) \
    ((Value + DivisorMacro - 1u) >> (DivisorMacro##_SHIFT))

#define BYTES_PER_CHUNK_SHIFT  12u
#define BYTES_PER_CHUNK        (1u << BYTES_PER_CHUNK_SHIFT)

typedef UINT32 CHUNK_NUM;

STATIC_ASSERT(
    MAX_BITS_PER_TABLE0_SHIFT == 44,
    "TABLE0 must cover a 44-bit page#.");

#endif // _included_OfflineDumpRedactionMapInternal_h
