// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <OfflineDumpLib.h>

#include <Library/OfflineDumpPageSize.h>
#include <Library/OfflineDumpRedactionMapInternal.h>

#include <Library/DebugLib.h>

#define CONTEXT_INITIALIZED  0xA1

EFI_STATUS
GetOfflineDumpRedactionScratchBufferLength (
  IN  UINT64  HighestPhysicalAddress,
  OUT UINT32  *pLength
  )
{
  UINT32      Length;
  EFI_STATUS  Status;

  if (MAX_UINT64 == HighestPhysicalAddress) {
    Length = MAX_UINT32;
    Status = EFI_INVALID_PARAMETER;
  } else {
    OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  Context;
    OfflineDumpRedactionScratchBufferLength_Init (&Context);
    OfflineDumpRedactionScratchBufferLength_AddMemRange (&Context, 0, HighestPhysicalAddress + 1);

    UINT64  Length64;
    if (EFI_ERROR (OfflineDumpRedactionScratchBufferLength_Get (&Context, &Length64)) ||
        (Length64 > MAX_UINT32))
    {
      Length = MAX_UINT32;
      Status = EFI_INVALID_PARAMETER;
    } else {
      Length = (UINT32)Length64;
      Status = EFI_SUCCESS;
    }
  }

  *pLength = Length;
  return Status;
}

void
OfflineDumpRedactionScratchBufferLength_Init (
  OUT OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  *pContext
  )
{
  pContext->LastPageNum = -1;
  pContext->BitmapCount = 0;
  pContext->Table1Count = 0;
  pContext->Initialized = CONTEXT_INITIALIZED;
  pContext->AnyErrors   = FALSE;
}

EFI_STATUS
OfflineDumpRedactionScratchBufferLength_AddMemRange (
  IN OUT OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT  *pContext,
  IN UINT64                                                    BaseAddress,
  IN UINT64                                                    Length
  )
{
  ASSERT (CONTEXT_INITIALIZED == pContext->Initialized);

  INT64 const  BeginPageNum = BaseAddress >> OD_PAGE_SIZE_SHIFT;
  INT64 const  PageCount    = Length >> OD_PAGE_SIZE_SHIFT;
  INT64 const  EndPageNum   = BeginPageNum + PageCount;

  if ((CONTEXT_INITIALIZED != pContext->Initialized) || // Context not initialized.
      (0 != (BaseAddress & (OD_PAGE_SIZE - 1))) ||      // BaseAddress not aligned to OD_PAGE_SIZE.
      (0 != (Length & (OD_PAGE_SIZE - 1)))  ||          // Length not aligned to OD_PAGE_SIZE.
      (BeginPageNum < pContext->LastPageNum) ||         // Ranges overlap or out of order.
      (EndPageNum > MAX_BITS_PER_TABLE0))               // 56-bit address space limit.
  {
    pContext->AnyErrors = TRUE;
    return EFI_INVALID_PARAMETER;
  }

  if (PageCount != 0) {
    if ((pContext->LastPageNum >> BITS_PER_BITMAP_SHIFT) != (BeginPageNum >> BITS_PER_BITMAP_SHIFT)) {
      pContext->BitmapCount += 1; // New Bitmap chunk.
    }

    if ((pContext->LastPageNum >> BITS_PER_TABLE1_SHIFT) != (BeginPageNum >> BITS_PER_TABLE1_SHIFT)) {
      pContext->Table1Count += 1; // New Table1 chunk.
    }

    pContext->LastPageNum  = EndPageNum;
    pContext->BitmapCount += (UINT32)((PageCount - 1) >> BITS_PER_BITMAP_SHIFT);
    pContext->Table1Count += (UINT16)((PageCount - 1) >> BITS_PER_TABLE1_SHIFT);
  }

  return EFI_SUCCESS;
}

EFI_STATUS
OfflineDumpRedactionScratchBufferLength_Get (
  IN OFFLINE_DUMP_REDACTION_SCRATCH_BUFFER_LENGTH_CONTEXT const  *pContext,
  OUT UINT64                                                     *pLength
  )
{
  EFI_STATUS  Status;
  UINT64      Length;

  ASSERT (CONTEXT_INITIALIZED == pContext->Initialized);

  if ((CONTEXT_INITIALIZED != pContext->Initialized) || pContext->AnyErrors) {
    Length = MAX_UINT64;
    Status = EFI_INVALID_PARAMETER;
  } else {
    UINT32 const  Table0Items  = (UINT32)DIVIDE_AND_ROUND_UP (pContext->LastPageNum, BITS_PER_TABLE1);
    UINT32 const  Table0Bytes  = Table0Items * sizeof (CHUNK_NUM);
    UINT32 const  Table0Chunks = DIVIDE_AND_ROUND_UP (Table0Bytes, BYTES_PER_CHUNK);

    Length =
      TABLE0_CHUNK_SIZE * Table0Chunks +
      TABLE1_SIZE * pContext->Table1Count +
      (UINT64)BITMAP_SIZE * pContext->BitmapCount;
    Status = EFI_SUCCESS;
  }

  *pLength = Length;
  return Status;
}
