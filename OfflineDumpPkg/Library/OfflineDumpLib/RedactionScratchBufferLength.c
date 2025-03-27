// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <OfflineDumpLib.h>
#include <Library/OfflineDumpRedactionMapInternal.h>

#define PAGE_SHIFT     12u
#define BITS_PER_BYTE  8

EFI_STATUS
GetOfflineDumpRedactionScratchBufferLength (
  IN  UINT64  HighestPhysicalAddress,
  OUT UINT32  *pLength
  )
{
  static UINT32 const  Table0Size = 4 * 1024; // Minimal 4KB Table0 covers addresses up to 0xFFFFFFFFFFFFF.

  static UINT32 const    Table1Size            = BITMAPS_PER_TABLE1 * sizeof (UINT32); // Size in indexes * 4 bytes per index = size in bytes
  static unsigned const  AddressPerTable1Shift = BITS_PER_TABLE1_SHIFT + PAGE_SHIFT;   // 2^42 = 4TB

  static UINT32 const    BitmapSize            = BITS_PER_BITMAP / BITS_PER_BYTE;    // size in bits / 8 bits per byte = size in bytes
  static unsigned const  AddressPerBitmapShift = BITS_PER_BITMAP_SHIFT + PAGE_SHIFT; // 2^32 = 4GB

  // Larger addresses require more than 4GB of scratch space.
  if (HighestPhysicalAddress > 0x7FFDFFFFFFFF) {
    *pLength = 0xFFFFF000; // Largest valid scratch space size.
    return EFI_INVALID_PARAMETER;
  }

  UINT32  RequiredBytes = Table0Size;  // Minimal 4KB Table0.
  RequiredBytes += (UINT32)((HighestPhysicalAddress >> AddressPerTable1Shift) + 1) * Table1Size;
  RequiredBytes += (UINT32)((HighestPhysicalAddress >> AddressPerBitmapShift) + 1) * BitmapSize;

  *pLength = RequiredBytes;
  return EFI_SUCCESS;
}
