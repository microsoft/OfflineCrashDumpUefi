// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include "SecureConfigurationArm64.h"

#include <Library/OfflineDumpPageSize.h>
#include <Library/OfflineDumpRedactionMapInternal.h>
#include <Library/OfflineDumpLib.h>

#include <AArch64/AArch64Mmu.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

#define ENTRIES_PER_TABLE_SHIFT        9 // 2^9 entries = 512 entries = 4KB granule / 8 bytes per entry
#define CONCATENATED_TABLES_MAX_SHIFT  4 // Max of 16 (2^4) concatenated tables.

typedef long long unsigned llu_t; // For printing UINT64s

/*
ARM64 Secure Configuration structures (from "Windows OffCD SK Memory Protection for ARM64.pdf"):
*/

typedef struct {
  UINT32    HeaderCrc32;
  UINT8     Version;         // = 0x1
  UINT8     EntryCount;      // Number of entries in the array.
  UINT16    EntryOffset;     // Bytes from start of this struct to first entry.
  UINT16    EntrySize;       // Size of each entry.
  UINT16    Res0;
  UINT32    Res1;
} OFFDUMP_HEADER;
STATIC_ASSERT (sizeof (OFFDUMP_HEADER) == 0x10, "OFFDUMP_HEADER size mismatch");

typedef enum OFFDUMP_ENTRY_TYPE {
  OFFDUMP_ENTRY_TYPE_INVALID        = 0,
  OFFDUMP_ENTRY_TYPE_SCRATCH_BUFFER = 1,
  OFFDUMP_ENTRY_TYPE_MEMLIST        = 2,
  OFFDUMP_ENTRY_TYPE_S2PT           = 3
} OFFDUMP_ENTRY_TYPE;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY_TYPE) == 4, "OFFDUMP_ENTRY_TYPE size mismatch");

typedef struct OFFDUMP_ENTRY {
  UINT32    EntryCrc32;
  UINT8     EntryType;     // Value from the OFFDUMP_ENTRY_TYPE enum.
  UINT8     Res0_1;        // Reserved.

  //
  // Size of the associated OFFDUMP_ENTRY_* struct.
  // Does not include the size of any further buffers
  // referenced by the entry itself.
  //
  UINT16    EntrySize;

  //
  // Bytes from the start of this struct to the start of
  // the associated OFFDUMP_ENTRY_* struct.
  //
  UINT16    EntryOffset;
  UINT16    Res0_2;     // Reserved.
  UINT32    Res0_3;     // Reserved.
} OFFDUMP_ENTRY;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY) == 0x10, "OFFDUMP_ENTRY size mismatch");

// There will be no more than one Scratch Buffer entry.
typedef struct OFFDUMP_ENTRY_SCRATCH_BUFFER {
  UINT32    EntryCrc32;
  UINT32    Res0_1;         // Reserved.
  UINT64    BufferSpa;      // Physical address, multiple of page size.
  UINT32    BufferSize;     // Multiple of page size.
  UINT32    Res0;           // Reserved.
} OFFDUMP_ENTRY_SCRATCH_BUFFER;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY_SCRATCH_BUFFER) == 0x18, "OFFDUMP_ENTRY_SCRATCH_BUFFER size mismatch");

// There will be one Memlist entry. It will contain non-overlapping items.
typedef struct OFFDUMP_ENTRY_MEMLIST {
  UINT32    EntryCrc32;
  UINT16    ItemSize;       // Size of each item.
  UINT16    ItemOffset;     // Bytes from start of this struct to first item.
  UINT16    ItemCount;      // Number of items.
  UINT16    Res0_1;         // Reserved.
  UINT32    ItemsCRC;       // CRC of the MEMLIST_ITEM array.
} OFFDUMP_ENTRY_MEMLIST;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY_MEMLIST) == 0x10, "OFFDUMP_ENTRY_MEMLIST size mismatch");

typedef struct OFFDUMP_ENTRY_MEMLIST_ITEM {
  UINT64    BaseSpa;     // Physical address, multiple of page size.
  UINT64    Size;        // Region size, multiple of page size
} OFFDUMP_ENTRY_MEMLIST_ITEM;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY_MEMLIST_ITEM) == 0x10, "OFFDUMP_ENTRY_MEMLIST_ITEM size mismatch");

// There will be one S2PT item.
typedef struct OFFDUMP_ENTRY_S2PT {
  UINT32    EntryCrc32;
  UINT32    Res0_1;
  UINT64    VTCR_EL2;
  UINT64    VTTBR_EL2;
} OFFDUMP_ENTRY_S2PT;
STATIC_ASSERT (sizeof (OFFDUMP_ENTRY_S2PT) == 0x18, "OFFDUMP_ENTRY_S2PT size mismatch");

/*
ARM64 CPU structures:
*/

typedef struct VTCR_EL2 {
  UINT32    T0SZ        : 6;   // region size is 2^(64-T0SZ) bytes
  UINT32    SL0         : 2;   // Starting level of the stage 2 translation lookup
  UINT32    IRGN0       : 2;   // Inner cacheability attribute for memory associated with translation table walks
  UINT32    ORGN0       : 2;   // Outer cacheability attribute for memory associated with translation table walks
  UINT32    SH0         : 2;   // Shareability attribute for memory associated with translation table walks
  UINT32    TG0         : 2;   // Granule size
  UINT32    PS          : 3;   // Physical address Size
  UINT32    VS          : 1;   // 16-bit VMID
  UINT32    RES0_20     : 1;
  UINT32    HA          : 1;   // Access flag update
  UINT32    HD          : 1;   // hardware management of dirty state
  UINT32    RES0_23     : 2;
  UINT32    HWU59       : 1;   // Bit[59] of each stage 2 translation table Block or Page entry is hardware-owned
  UINT32    HWU60       : 1;   // Bit[60] of each stage 2 translation table Block or Page entry is hardware-owned
  UINT32    HWU61       : 1;   // Bit[61] of each stage 2 translation table Block or Page entry is hardware-owned
  UINT32    HWU62       : 1;   // Bit[62] of each stage 2 translation table Block or Page entry is hardware-owned
  UINT32    NSW         : 1;   // Translation walks to Non-secure PA space
  UINT32    NSA         : 1;   // Translations access Non-secure PA space
  UINT32    RES1_31     : 1;
  UINT32    DS          : 1;   // output address[51,50,49,48] = translation descriptor[9,8,49,48]
  UINT32    SL2         : 1;   // Starting level of the stage 2 translation lookup (with SL0)
  UINT32    AssuredOnly : 1;   // Bit[58] of each stage 2 translation Block or Page descriptor is AssuredOnly attribute
  UINT32    TL1         : 1;   // MMU TopLevel1 permission attribute check
  UINT32    S2PIE       : 1;   // permission indirection in stage 2 Permission model
  UINT32    S2POE       : 1;   // permission overlay in stage 2 Permission model
  UINT32    D128        : 1;   // VMSAv9-128 translation process
  UINT32    RES0_39     : 1;
  UINT32    GCSH        : 1;   // privileged Guarded Control Stack data accesses: AssuredOnly attribute in stage 2 is required
  UINT32    TL0         : 1;   // MMU TopLevel0 permission attribute check
  UINT32    RES0_42     : 2;
  UINT32    HAFT        : 1;   // Hardware managed Access Flag for Table descriptors
  UINT32    HDBSS       : 1;   // Hardware tracking of Dirty state Structure
  UINT32    RES0_34     :18;
} VTCR_EL2;
STATIC_ASSERT (sizeof (VTCR_EL2) == sizeof (UINT64), "VTCR_EL2 size mismatch");

typedef struct VTTBR_EL2 {
  UINT64    CnP   : 1;   // Common not Private
  UINT64    BADDR :47;   // Translation table base address [47:1]
  UINT64    VMID  :16;   // The VMID for the translation table
} VTTBR_EL2;
STATIC_ASSERT (sizeof (VTTBR_EL2) == sizeof (UINT64), "VTCR_EL2 size mismatch");

// Get output address for the Page/Block/Table descriptor, assuming 4KB granule, 48-bit OA.
// If this is a block descriptor, caller needs to clear bits [15:12].
static UINT64
DescriptorOutputAddress48 (
  UINT64  Descriptor
  )
{
  // Bits  [47:12] of the address are in bits [47:12] of the descriptor.
  ASSERT (Descriptor & 1); // Valid descriptor.
  return (Descriptor & TT_ADDRESS_MASK_DESCRIPTION_TABLE);
}

// Get output address for the Page/Block/Table descriptor, assuming 4KB granule, 52-bit OA.
// If this is a block descriptor, caller needs to clear bits [15:12].
static UINT64
DescriptorOutputAddress52 (
  UINT64  Descriptor
  )
{
  // Bits  [51:12] of the address are in bits [9:8][49:12] of the descriptor.
  ASSERT (Descriptor & 1); // Valid descriptor.
  return (Descriptor & 0x0003FFFFFFFFF000) | ((Descriptor & 0x300) << 42);
}

/*
ARM64 helpers:
*/

// Returns StartOffset + (ItemCount * ItemSize).
// Overflow is impossible (maximum possible result is 0xFFFF0000).
static UINT32
MakeEndOffset (
  UINT16  StartOffset,
  UINT16  ItemCount,
  UINT16  ItemSize
  )
{
  STATIC_ASSERT (0xFFFFllu + 0xFFFFllu * 0xFFFFu <= MAX_UINT32, "Overflow possible");
  return StartOffset + ItemCount * (UINT32)ItemSize;
}

static BOOLEAN
IsMultipleOfPageSize (
  IN UINT64  Value
  )
{
  return 0 == (Value & (OD_PAGE_SIZE - 1));
}

typedef struct {
  OFFDUMP_HEADER const    *pHeader;
  UINT32                  EndOffset;
  UINT32                  CurrentOffset;
} ENTRY_ENUMERATOR;

// Assumes that pHeader has been validated.
static ENTRY_ENUMERATOR
EntryEnumeratorCreate (
  IN OFFDUMP_HEADER const  *pHeader
  )
{
  ENTRY_ENUMERATOR  Enumerator;

  Enumerator.pHeader       = pHeader;
  Enumerator.EndOffset     = MakeEndOffset (pHeader->EntryOffset, pHeader->EntryCount, pHeader->EntrySize);
  Enumerator.CurrentOffset = pHeader->EntryOffset;

  return Enumerator;
}

static BOOLEAN
EntryEnumeratorNext (
  IN OUT ENTRY_ENUMERATOR  *pEnumerator,
  OUT void const           **ppStructEntry,
  OUT OFFDUMP_ENTRY_TYPE   *pStructEntryType
  )
{
  if (pEnumerator->CurrentOffset >= pEnumerator->EndOffset) {
    ASSERT (pEnumerator->CurrentOffset == pEnumerator->EndOffset);
    *ppStructEntry    = NULL;
    *pStructEntryType = OFFDUMP_ENTRY_TYPE_INVALID;
    return FALSE;
  }

  OFFDUMP_ENTRY const * const  pEntry =
    (OFFDUMP_ENTRY const *)((UINT8 const *)pEnumerator->pHeader + pEnumerator->CurrentOffset);
  pEnumerator->CurrentOffset += pEntry->EntrySize;

  *ppStructEntry    = (UINT8 const *)(pEntry) + pEntry->EntryOffset;
  *pStructEntryType = pEntry->EntryType;
  return TRUE;
}

typedef struct {
  OFFDUMP_ENTRY_MEMLIST const    *pMemlist;
  UINT32                         EndOffset;
  UINT32                         CurrentOffset;
} MEMLIST_ITEM_ENUMERATOR;

// Assumes that pMemlist has been validated.
static MEMLIST_ITEM_ENUMERATOR
MemlistItemEnumeratorCreate (
  IN OFFDUMP_ENTRY_MEMLIST const  *pMemlist
  )
{
  MEMLIST_ITEM_ENUMERATOR  Enumerator;

  Enumerator.pMemlist      = pMemlist;
  Enumerator.EndOffset     = MakeEndOffset (pMemlist->ItemOffset, pMemlist->ItemCount, pMemlist->ItemSize);
  Enumerator.CurrentOffset = pMemlist->ItemOffset;

  return Enumerator;
}

static BOOLEAN
MemlistItemEnumeratorNext (
  IN OUT MEMLIST_ITEM_ENUMERATOR        *pEnumerator,
  OUT OFFDUMP_ENTRY_MEMLIST_ITEM const  **ppItem
  )
{
  if (pEnumerator->CurrentOffset >= pEnumerator->EndOffset) {
    *ppItem = NULL;
    return FALSE;
  }

  OFFDUMP_ENTRY_MEMLIST_ITEM const * const  pItem =
    (OFFDUMP_ENTRY_MEMLIST_ITEM const *)((UINT8 const *)pEnumerator->pMemlist + pEnumerator->CurrentOffset);
  pEnumerator->CurrentOffset += pEnumerator->pMemlist->ItemSize;

  *ppItem = pItem;
  return TRUE;
}

// Assumes struct starts with a UINT32 Crc field.
// Skips that field and computes CRC32 of the rest of the struct.
// Print error and return FALSE if the CRC32 does not match.
static UINT32
StructCrcOk (
  IN char const  *Name,
  IN VOID const  *pStruct,
  IN UINT32      StructSize
  )
{
  ASSERT (StructSize >= sizeof (UINT32));
  UINT32 const  Expected = *(UINT32 const *)pStruct;
  UINT32 const  Actual   = CalculateCrc32 ((UINT8 *)pStruct + sizeof (UINT32), StructSize - sizeof (UINT32));
  if (Expected != Actual) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "%a CRC32 mismatch: expected 0x%X, got 0x%X\n",
                 Name,
                 Expected,
                 Actual
                 );
    return FALSE;
  }

  return TRUE;
}

static BOOLEAN
Validate_OFFDUMP_ENTRY (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  IN UINT32                                 EntryOffset,
  IN UINT32                                 EntrySize
  )
{
  UINT32 const  ConfigSize    = pDumpInfo->SecureConfigurationSize;
  UINT8 const   *pConfigBytes = pDumpInfo->pSecureConfiguration;

  // Caller is responsible for the following:
  ASSERT (EntryOffset + EntrySize <= ConfigSize);
  ASSERT (EntrySize >= sizeof (OFFDUMP_ENTRY));

  OFFDUMP_ENTRY const * const  pEntry = (OFFDUMP_ENTRY const *)(pConfigBytes + EntryOffset);

  if (!StructCrcOk ("OFFDUMP_ENTRY", pEntry, EntrySize)) {
    return FALSE;
  }

  OFFDUMP_ENTRY_TYPE const  StructEntryType = pEntry->EntryType;

  UINT16 const  StructEntrySize = pEntry->EntrySize;
  if (StructEntrySize < sizeof (UINT32)) {
    DEBUG_PRINT (DEBUG_ERROR, "StructEntrySize %u < sizeof(CRC32)\n", StructEntrySize);
    return FALSE;
  }

  UINT32 const  StructEntryOffset = EntryOffset + pEntry->EntryOffset;
  if (StructEntryOffset < EntryOffset) {
    DEBUG_PRINT (DEBUG_ERROR, "StructEntryOffset %u < EntryOffset %u (overflow)\n", StructEntryOffset, EntryOffset);
    return FALSE;
  }

  UINT32 const  StructEntryEndOffset = StructEntryOffset + StructEntrySize;
  if ((StructEntryEndOffset < StructEntryOffset) || (StructEntryEndOffset > ConfigSize)) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "StructEntryOffset %u + StructEntrySize %u > ConfigSize %u\n",
                 StructEntryOffset,
                 StructEntrySize,
                 ConfigSize
                 );
    return FALSE;
  }

  void const  *const  pStructEntry = pConfigBytes + StructEntryOffset;
  if (!StructCrcOk ("OFFDUMP_ENTRY::Struct", pStructEntry, StructEntrySize)) {
    return FALSE;
  }

  switch (StructEntryType) {
    default:
    {
      DEBUG_PRINT (DEBUG_ERROR, "Unsupported entry type %u\n", StructEntryType);
      return FALSE;
    }

    case OFFDUMP_ENTRY_TYPE_SCRATCH_BUFFER:
    {
      if (StructEntrySize < sizeof (OFFDUMP_ENTRY_SCRATCH_BUFFER)) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "StructEntrySize %u < sizeof(OFFDUMP_ENTRY_SCRATCH_BUFFER) %u\n",
                     StructEntrySize,
                     (unsigned)sizeof (OFFDUMP_ENTRY_SCRATCH_BUFFER)
                     );
        return FALSE;
      }

      OFFDUMP_ENTRY_SCRATCH_BUFFER const * const  pScratchBuffer = (OFFDUMP_ENTRY_SCRATCH_BUFFER const *)pStructEntry;

      if (!IsMultipleOfPageSize (pScratchBuffer->BufferSize)) {
        DEBUG_PRINT (DEBUG_ERROR, "Invalid ScratchBufferSize %u\n", pScratchBuffer->BufferSize);
        return FALSE;
      }

      if (!IsMultipleOfPageSize (pScratchBuffer->BufferSpa)) {
        DEBUG_PRINT (DEBUG_ERROR, "Invalid ScratchBufferSpa 0x%llX\n", (llu_t)pScratchBuffer->BufferSpa);
        return FALSE;
      }

      break;
    }

    case OFFDUMP_ENTRY_TYPE_MEMLIST:
    {
      if (StructEntrySize < sizeof (OFFDUMP_ENTRY_MEMLIST)) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "StructEntrySize %u < sizeof(OFFDUMP_ENTRY_MEMLIST) %u\n",
                     StructEntrySize,
                     (unsigned)sizeof (OFFDUMP_ENTRY_MEMLIST)
                     );
        return FALSE;
      }

      OFFDUMP_ENTRY_MEMLIST const * const  pMemlist = (OFFDUMP_ENTRY_MEMLIST const *)pStructEntry;

      UINT16 const  ItemSize = pMemlist->ItemSize;
      if (ItemSize < sizeof (OFFDUMP_ENTRY_MEMLIST_ITEM)) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "ItemSize %u < sizeof(OFFDUMP_ENTRY_MEMLIST_ITEM) %u\n",
                     ItemSize,
                     (unsigned)sizeof (OFFDUMP_ENTRY_MEMLIST_ITEM)
                     );
        return FALSE;
      }

      UINT32 const  ItemsOffset = StructEntryOffset + pMemlist->ItemOffset;
      if (ItemsOffset < StructEntryOffset) {
        DEBUG_PRINT (DEBUG_ERROR, "ItemOffset %u < StructEntryOffset %u (overflow)\n", ItemsOffset, StructEntryOffset);
        return FALSE;
      }

      UINT32 const  ItemsSizeTotal = pMemlist->ItemCount * (UINT32)ItemSize;

      UINT32 const  ItemsEndOffset = ItemsOffset + ItemsSizeTotal;
      if ((ItemsEndOffset < ItemsOffset) || (ItemsEndOffset > ConfigSize)) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "ItemOffset %u + ItemCount %u * ItemSize %u > ConfigSize %u\n",
                     ItemsOffset,
                     pMemlist->ItemCount,
                     ItemSize,
                     ConfigSize
                     );
        return FALSE;
      }

      UINT32 const  Crc32 = CalculateCrc32 (
                                            (UINT8 *)pConfigBytes + ItemsOffset,
                                            ItemsSizeTotal
                                            );
      if (pMemlist->ItemsCRC != Crc32) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "ItemsCRC mismatch: expected 0x%X, got 0x%X\n",
                     pMemlist->ItemsCRC,
                     Crc32
                     );
      }

      MEMLIST_ITEM_ENUMERATOR           ItemEnum = MemlistItemEnumeratorCreate (pMemlist);
      OFFDUMP_ENTRY_MEMLIST_ITEM const  *pItem;

      while (MemlistItemEnumeratorNext (&ItemEnum, &pItem)) {
        if (!IsMultipleOfPageSize (pItem->BaseSpa)) {
          DEBUG_PRINT (DEBUG_ERROR, "Invalid BaseSpa 0x%llX\n", (llu_t)pItem->BaseSpa);
          return FALSE;
        }

        if (!IsMultipleOfPageSize (pItem->Size)) {
          DEBUG_PRINT (DEBUG_ERROR, "Invalid Size 0x%X\n", (llu_t)pItem->Size);
          return FALSE;
        }

        if (pItem->BaseSpa + pItem->Size < pItem->BaseSpa) {
          DEBUG_PRINT (
                       DEBUG_ERROR,
                       "BaseSpa 0x%llX + Size 0x%llX < BaseSpa 0x%llX (overflow)\n",
                       (llu_t)pItem->BaseSpa,
                       (llu_t)pItem->Size,
                       (llu_t)pItem->BaseSpa
                       );
          return FALSE;
        } else if (pItem->BaseSpa + pItem->Size > (MAX_UINT64 >> 8)) {
          DEBUG_PRINT (
                       DEBUG_ERROR,
                       "BaseSpa 0x%llX + Size 0x%llX >= 2^56\n",
                       (llu_t)pItem->BaseSpa,
                       (llu_t)pItem->Size
                       );
          return FALSE;
        }
      }

      break;
    }

    case OFFDUMP_ENTRY_TYPE_S2PT:
    {
      if (StructEntrySize < sizeof (OFFDUMP_ENTRY_S2PT)) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "StructEntrySize %u < sizeof(OFFDUMP_ENTRY_S2PT) %u\n",
                     StructEntrySize,
                     (unsigned)sizeof (OFFDUMP_ENTRY_S2PT)
                     );
        return FALSE;
      }

      break;
    }
  }

  return TRUE;
}

static BOOLEAN
Validate_OFFDUMP_HEADER (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo
  )
{
  UINT32 const  ConfigSize    = pDumpInfo->SecureConfigurationSize;
  UINT8 const   *pConfigBytes = pDumpInfo->pSecureConfiguration;

  if (ConfigSize < sizeof (OFFDUMP_HEADER)) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "SecureConfigurationSize provided %u < sizeof(OFFDUMP_HEADER) %u\n",
                 ConfigSize,
                 (unsigned)sizeof (OFFDUMP_HEADER)
                 );
    return FALSE;
  }

  OFFDUMP_HEADER const * const  pHeader = (OFFDUMP_HEADER const *)pConfigBytes;
  if (!StructCrcOk ("OFFDUMP_HEADER", pHeader, sizeof (*pHeader))) {
    return FALSE;
  }

  if (pHeader->Version != 1) {
    DEBUG_PRINT (DEBUG_ERROR, "Unsupported header version %u\n", pHeader->Version);
    return FALSE;
  }

  UINT16 const  EntrySize        = pHeader->EntrySize;
  UINT16 const  EntriesOffset    = pHeader->EntryOffset;
  UINT32 const  EntriesEndOffset = MakeEndOffset (EntriesOffset, pHeader->EntryCount, EntrySize);
  if (EntriesEndOffset > ConfigSize) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "EntriesOffset %u + EntryCount %u * EntrySize %u > ConfigSize %u\n",
                 EntriesOffset,
                 pHeader->EntryCount,
                 EntrySize,
                 ConfigSize
                 );
    return FALSE;
  }

  if (EntrySize < sizeof (OFFDUMP_ENTRY)) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "EntrySize %u < sizeof(OFFDUMP_ENTRY) %u\n",
                 EntrySize,
                 (unsigned)sizeof (OFFDUMP_ENTRY)
                 );
    return FALSE;
  }

  for (UINT32 EntryOffset = EntriesOffset; EntryOffset != EntriesEndOffset; EntryOffset += EntrySize) {
    ASSERT (EntryOffset < ConfigSize);
    if (!Validate_OFFDUMP_ENTRY (pDumpInfo, EntryOffset, pHeader->EntrySize)) {
      return FALSE;
    }
  }

  return TRUE;
}

static void
WalkPageTableLevel3 (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN UINT64 const                    *pEntries,
  IN UINT32                          EntryCount,
  IN BOOLEAN                         Oa52
  )
{
  if (Oa52) {
    for (UINT32 i = 0; i != EntryCount; i += 1) {
      UINT64 const  Entry = pEntries[i];
      if (TT_TYPE_TABLE_ENTRY == (Entry & TT_TYPE_MASK)) {
        // 3 = Page descriptor.
        UINT64 const  PageAddress = DescriptorOutputAddress52 (Entry);
        OfflineDumpRedactionMap_ExposePage (pMap, PageAddress >> OD_PAGE_SIZE_SHIFT);
      } else {
        // 0 or 2 = Invalid entry (page not present).
        // 1 = Invalid entry (reserved).
      }
    }
  } else {
    for (UINT32 i = 0; i != EntryCount; i += 1) {
      UINT64 const  Entry = pEntries[i];
      if (TT_TYPE_TABLE_ENTRY == (Entry & TT_TYPE_MASK)) {
        // 3 = Page descriptor.
        UINT64 const  PageAddress = DescriptorOutputAddress48 (Entry);
        OfflineDumpRedactionMap_ExposePage (pMap, PageAddress >> OD_PAGE_SIZE_SHIFT);
      } else {
        // 0 or 2 = Invalid entry (page not present).
        // 1 = Invalid entry (reserved).
      }
    }
  }
}

static void
WalkPageTableLevelN (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN UINT64 const                    *pEntries,
  IN UINT32                          EntryCount,
  IN BOOLEAN                         Oa52,
  IN UINT8                           AdditionalTableLevels
  )
{
  for (UINT32 i = 0; i != EntryCount; i += 1) {
    UINT64 const  Entry = pEntries[i];
    switch (Entry & TT_TYPE_MASK) {
      case TT_TYPE_BLOCK_ENTRY:
      {
        // 1 = Block descriptor.
        UINT64 const  OutputAddress = Oa52 ? DescriptorOutputAddress52 (Entry) : DescriptorOutputAddress48 (Entry);
        UINT64 const  BlockAddress  = OutputAddress & 0xFFFFFFFFFFFF0000; // 64KB-aligned block.
        UINT64 const  BlockPageNum  = BlockAddress >> OD_PAGE_SIZE_SHIFT;

        if (AdditionalTableLevels > 2) {
          // L(-1) blocks are undefined.
          continue;
        }

        // 0 (L2) = 2MB blocks (2^9 pages).
        // 1 (L1) = 1GB blocks (2^18 pages).
        // 2 (L0) = 512GB blocks (2^27 pages).
        UINT32 const  BlockPageCount = BIT9 << (9 * AdditionalTableLevels);

        OfflineDumpRedactionMap_MarkRange (
                                           pMap,
                                           FALSE,
                                           BlockPageNum,
                                           BlockPageNum + BlockPageCount
                                           );
        break;
      }

      case TT_TYPE_TABLE_ENTRY:
      {
        // 3 = Table descriptor.
        UINT64 const  TableAddress = Oa52 ? DescriptorOutputAddress52 (Entry) : DescriptorOutputAddress48 (Entry);
        if (0 != AdditionalTableLevels) {
          WalkPageTableLevelN (pMap, (UINT64 const *)TableAddress, BIT9, Oa52, AdditionalTableLevels - 1);
        } else {
          WalkPageTableLevel3 (pMap, (UINT64 const *)TableAddress, BIT9, Oa52);
        }

        break;
      }

      default:
      {
        // 0 or 2 = Invalid entry (page not present).
        break;
      }
    }
  }
}

static void
AddS2Pt (
  IN OUT OFFLINE_DUMP_REDACTION_MAP  *pMap,
  IN OFFDUMP_ENTRY_S2PT const        *pS2pt
  )
{
  VTCR_EL2  Vtcr;

  CopyMem (&Vtcr, &pS2pt->VTCR_EL2, sizeof (Vtcr));

  // static UINT8 const  PsToPaSize[] = { 32, 36, 40, 42, 44, 48, 52, 56 };
  // UINT8 const         PaSize       = PsToPaSize[Vtcr.PS];

  // 52-bit output address?
  BOOLEAN const  Oa52 = 0 != Vtcr.DS;

  // Currently only support 4KB translation granule.
  if (Vtcr.TG0 != 0) {
    DEBUG_PRINT (DEBUG_ERROR, "Unsupported VTCR_EL2.TG0 %u\n", Vtcr.TG0);
    return;
  }

  // AdditionalTableLevels = 3 - StartLevel.
  static UINT8 const  CombinedSlToAdditionalTableLevels[] = {
    1, // StartLevel = 2
    2, // StartLevel = 1
    3, // StartLevel = 0
    0, // StartLevel = 3
    4, // StartLevel = -1
  };

  // Combine SL0 with SL2 to create an index into CombinedSlToAdditionalTableLevels.
  UINT32 const  CombinedSl = Vtcr.SL0 | ((Vtcr.DS ? Vtcr.SL2 : 0u) << 2);
  if (CombinedSl >= ARRAY_SIZE (CombinedSlToAdditionalTableLevels)) {
    DEBUG_PRINT (DEBUG_ERROR, "Unsupported VTCR_EL2.CombinedSL %u\n", CombinedSl);
    return;
  }

  // AdditionalTableLevels = 3 - StartLevel.
  UINT8 const  AdditionalTableLevels = CombinedSlToAdditionalTableLevels[CombinedSl];

  // Intermediate Physical Address has 64-T0SZ valid bits.
  UINT8 const  IpaBits = 64 - (UINT8)Vtcr.T0SZ;

  // Make sure the input region size is reasonable for the number of lookup levels.
  // The following minimum and maximum values are less strict than the AARCH64 spec
  // but they are enough to ensure that our code behaves reasonably.
  // AARCH64 allows 16..8192 entries for L3, 2..8192 for L2-L0, and 2..512 for L(-1).
  // These rules allow 1..8192 entries for all table levels.

  // For AdditionalTableLevels=0 (StartLevel=3): minimum we allow is 1<<0 entries.
  // Each additional table level adds ENTRIES_PER_TABLE_SHIFT bits.
  // Maximum is 1<<13 entries (1<<9 entries/table * 1<<4 concatenated tables).
  UINT8 const  IpaBitsMin = OD_PAGE_SIZE_SHIFT + (ENTRIES_PER_TABLE_SHIFT * AdditionalTableLevels);
  UINT8 const  IpaBitsMax = IpaBitsMin + (ENTRIES_PER_TABLE_SHIFT + CONCATENATED_TABLES_MAX_SHIFT);

  if (IpaBits < IpaBitsMin) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "Unsupported VTCR_EL2.T0SZ %u > maximum %u for StartLevel %d\n",
                 Vtcr.T0SZ,
                 64 - IpaBitsMin,
                 3 - AdditionalTableLevels
                 );
    return;
  } else if (IpaBits > IpaBitsMax) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "Unsupported VTCR_EL2.T0SZ %u < minimum %u for StartLevel %d\n",
                 Vtcr.T0SZ,
                 64 - IpaBitsMax,
                 3 - AdditionalTableLevels
                 );
    return;
  }

  // Find the base address of the initial level.
  UINT64 const  Baddr = Oa52
    ? (pS2pt->VTTBR_EL2 & 0x0000FFFFFFFFFFC0) | (pS2pt->VTTBR_EL2 & 0x3C) << 46
    : (pS2pt->VTTBR_EL2 & 0x0000FFFFFFFFFFFE);
  if (Baddr & 0x7) {
    DEBUG_PRINT (DEBUG_ERROR, "Misaligned BADDR 0x%llX (VTTBR_EL2 = 0x%llX)\n", (llu_t)Baddr, (llu_t)pS2pt->VTTBR_EL2);
    return;
  }

  // Initial level has variable size from 1<<0 (1) to 1<<13 (8192) entries.
  // Additional levels are always 1<<9 (512) entries.
  UINT32 const  EntryCount = 1u << (IpaBits - IpaBitsMin);
  if (AdditionalTableLevels) {
    WalkPageTableLevelN (pMap, (UINT64 const *)Baddr, EntryCount, Oa52, AdditionalTableLevels - 1);
  } else {
    WalkPageTableLevel3 (pMap, (UINT64 const *)Baddr, EntryCount, Oa52);
  }
}

EFI_STATUS
OfflineDumpSecureConfigurationArm64_PrepareRedactionMap (
  IN OFFLINE_DUMP_PROVIDER_DUMP_INFO const  *pDumpInfo,
  OUT OFFLINE_DUMP_REDACTION_MAP            *pMap
  )
{
  EFI_STATUS          Status;
  ENTRY_ENUMERATOR    EntryEnum;
  void const          *pStructEntry;
  OFFDUMP_ENTRY_TYPE  StructEntryType;

  // Pass 0: Validate the header and entries.
  // Failure is fatal.

  if (!Validate_OFFDUMP_HEADER (pDumpInfo)) {
    return EFI_COMPROMISED_DATA;
  }

  // Pass 1: Find data needed to initialze the bitmap (scratch buffer and max page number).
  // Failure to locate scratch buffer is fatal.

  {
    // Required for the call to OfflineDumpRedactionMap_Init.
    UINT64  MaxPageNumber     = 0;
    UINT64  ScratchBufferAddr = 0;
    UINT32  ScratchBufferSize = 0;

    // Best-effort, used only for DEBUG_PRINT output.
    OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  RequiredSizeContext;
    OfflineDumpRedactionScratchBufferLength_Init (&RequiredSizeContext);

    EntryEnum = EntryEnumeratorCreate ((OFFDUMP_HEADER const *)pDumpInfo->pSecureConfiguration);
    while (EntryEnumeratorNext (&EntryEnum, &pStructEntry, &StructEntryType)) {
      switch (StructEntryType) {
        case OFFDUMP_ENTRY_TYPE_MEMLIST:
        {
          MEMLIST_ITEM_ENUMERATOR           ItemEnum;
          OFFDUMP_ENTRY_MEMLIST_ITEM const  *pItem;

          ItemEnum = MemlistItemEnumeratorCreate ((OFFDUMP_ENTRY_MEMLIST const *)pStructEntry);
          while (MemlistItemEnumeratorNext (&ItemEnum, &pItem)) {
            UINT64 const  BasePageNum = pItem->BaseSpa >> OD_PAGE_SIZE_SHIFT;

            if (BasePageNum < MaxPageNumber) {
              ASSERT (FALSE); // Should have been checked during validation.
              return EFI_COMPROMISED_DATA;
            }

            MaxPageNumber = BasePageNum + (pItem->Size >> OD_PAGE_SIZE_SHIFT);

            if (EFI_ERROR (
                           OfflineDumpRedactionScratchBufferLength_AddMemRange (
                                                                                &RequiredSizeContext,
                                                                                pItem->BaseSpa,
                                                                                pItem->Size
                                                                                )
                           ))
            {
              // This is probably impossible (should have been checked during validation).
              // Not fatal - just print a warning.
              DEBUG_PRINT (
                           DEBUG_WARN,
                           "Invalid MemList item Base=0x%llX, Size=0x%llX\n",
                           (llu_t)pItem->BaseSpa,
                           (llu_t)pItem->Size
                           );
            }
          }

          break;
        }

        case OFFDUMP_ENTRY_TYPE_SCRATCH_BUFFER:
        {
          OFFDUMP_ENTRY_SCRATCH_BUFFER const * const  pScratchBuffer = (OFFDUMP_ENTRY_SCRATCH_BUFFER const *)pStructEntry;

          if (ScratchBufferSize != 0) {
            DEBUG_PRINT (DEBUG_WARN, "Multiple ScratchBuffer entries\n");
          } else {
            ScratchBufferAddr = pScratchBuffer->BufferSpa;
            ScratchBufferSize = pScratchBuffer->BufferSize;
          }

          break;
        }
      }
    }

    UINT64  RequiredSize;
    Status = OfflineDumpRedactionScratchBufferLength_Get (&RequiredSizeContext, &RequiredSize);
    if (EFI_ERROR (Status)) {
      // Unexpected, probably a bug in validation, not fatal.
      DEBUG_PRINT (
                   DEBUG_ERROR,
                   "ScratchBufferSize 0x%X, required size unknown\n",
                   ScratchBufferSize
                   );
    } else if (ScratchBufferSize < RequiredSize) {
      // Redaction will likely fail due to insufficient buffer.
      DEBUG_PRINT (
                   DEBUG_WARN,
                   "ScratchBufferSize 0x%X < required size 0x%llX\n",
                   ScratchBufferSize,
                   (llu_t)RequiredSize
                   );
    } else {
      // Buffer appears to be large enough.
      DEBUG_PRINT (
                   DEBUG_INFO,
                   "ScratchBufferSize 0x%X, required size 0x%llX\n",
                   ScratchBufferSize,
                   (llu_t)RequiredSize
                   );
    }

    Status = OfflineDumpRedactionMap_Init (
                                           pMap,
                                           (void *)ScratchBufferAddr,
                                           ScratchBufferSize,
                                           MaxPageNumber
                                           );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "OfflineDumpRedactionMap_Init() failed: %r\n", Status);
      return Status;
    }
  }

  // Pass 2: Mark bitmap based on memlists.
  // Failure is fatal.

  EntryEnum = EntryEnumeratorCreate ((OFFDUMP_HEADER const *)pDumpInfo->pSecureConfiguration);
  while (EntryEnumeratorNext (&EntryEnum, &pStructEntry, &StructEntryType)) {
    if (StructEntryType == OFFDUMP_ENTRY_TYPE_MEMLIST) {
      MEMLIST_ITEM_ENUMERATOR           ItemEnum;
      OFFDUMP_ENTRY_MEMLIST_ITEM const  *pItem;

      ItemEnum = MemlistItemEnumeratorCreate ((OFFDUMP_ENTRY_MEMLIST const *)pStructEntry);
      while (MemlistItemEnumeratorNext (&ItemEnum, &pItem)) {
        Status = OfflineDumpRedactionMap_MarkRange (
                                                    pMap,
                                                    TRUE,
                                                    pItem->BaseSpa >> OD_PAGE_SIZE_SHIFT,
                                                    (pItem->BaseSpa + pItem->Size) >> OD_PAGE_SIZE_SHIFT
                                                    );
        if (EFI_ERROR (Status)) {
          DEBUG_PRINT (DEBUG_ERROR, "OfflineDumpRedactionMap_Redact() failed: %r\n", Status);
          return Status;
        }
      }
    }
  }

  // Pass 3: Unmark bitmap based on stage-2 page tables.
  // Failure is non-fatal -- it just means we'll redact too much.

  EntryEnum = EntryEnumeratorCreate ((OFFDUMP_HEADER const *)pDumpInfo->pSecureConfiguration);
  while (EntryEnumeratorNext (&EntryEnum, &pStructEntry, &StructEntryType)) {
    if (StructEntryType == OFFDUMP_ENTRY_TYPE_S2PT) {
      AddS2Pt (pMap, (OFFDUMP_ENTRY_S2PT const *)pStructEntry);
    }
  }

  return EFI_SUCCESS;
}

BOOLEAN
OfflineDumpSecureConfigurationArm64_MustRedactCpuContext (
  IN OFFLINE_DUMP_REDACTION_MAP const                      *pMap,
  IN OFFLINE_DUMP_PROVIDER_SECURE_CPU_CONTEXT_ARM64 const  *pSecureCpuContext
  )
{
  PHYSICAL_ADDRESS  AddressToCheck = pSecureCpuContext->TTBR1_EL1 & 0x0000FFFFFFFFFFFE;
  BOOLEAN           MustRedact     = OfflineDumpRedactionMap_IsRedacted (pMap, AddressToCheck >> OD_PAGE_SIZE_SHIFT);

  return MustRedact;
}
