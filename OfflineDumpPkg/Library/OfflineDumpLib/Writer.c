#include <Library/OfflineDumpWriter.h>
#include <Library/OfflineDumpEncryptor.h>
#include <Library/OfflineDumpVariables.h>

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/BlockIo2.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Library/UefiLib.h>
#define DEBUG_PRINT(bits, ...)  _DEBUG_PRINT(bits, "DW: " __VA_ARGS__)

static const UINT8   BufferCountDefault       = 8;
static const UINT32  BufferMemoryLimitDefault = 0x100000; // 1 MB
static const UINT32  SectionCountMax          = (0x80000000 - sizeof (RAW_DUMP_HEADER)) / sizeof (RAW_DUMP_SECTION_HEADER);
static const UINT32  SectionAlign             = 16;

typedef struct DUMP_WRITER_BUFFER_INFO DUMP_WRITER_BUFFER_INFO;

struct DUMP_WRITER {
  ENCRYPTOR                             *pEncryptor;        // NULL if unencrypted.
  UINT8                                 *pHeaders;          // HeadersSize buffer for encHdr+dumpHdr+sectionHdrs (padded to a multiple of BlockSize).
  UINT8                                 *pHeadersSync;      // HeadersSyncSize buffer for writing headers. Used only when no async I/O support.
  DUMP_WRITER_BUFFER_INFO               *pBufferInfos;      // BufferCount buffers, each with room for BufferSize bytes.
  EFI_EVENT                             OperationCompleted; // Signaled by DW_BufferInfoOperationComplete.

  // Above this line: Allocations that must be freed during destruction.
  // Below this line: fields that are set up during construction and never modified.

  EFI_BLOCK_IO2_PROTOCOL                *pBlockIo2;           // Set if async IO is supported. If NULL, use pBlockIo for blocking IO.
  EFI_BLOCK_IO_PROTOCOL                 *pBlockIo;            // Set only if pBlockIo2 is NULL.
  UINT64                                MediaSize;            // Storage size of the device in bytes.
  UINT32                                MediaID;              // Media ID of the device (used to trigger error if media is changed).
  UINT32                                RawDumpOffset;        // Size of encryption headers (if any). RawDumpHeader is at &pHeaders[RawDumpOffset]
  UINT32                                HeadersSize;          // Size of pHeaders. This must be a multiple of BlockSize.
  UINT32                                HeadersSyncSize;      // Size of pHeadersSync. This must be a multiple of BlockSize.
  UINT32                                SectionCountExpected; // pHeaders has room for this many section headers.
  UINT32                                BufferSize;           // Size of each pBufferInfos buffer. Multiple of MediaBlockSize, multiple of EFI_PAGE_SIZE.
  UINT8                                 BufferCount;          // Number of pBufferInfos buffers.
  UINT8                                 MediaBlockShift;      // Log2 of MediaBlockSize.

  // Above this line: fields that are set up during construction and never modified.
  // Below this line: fields that are modified during operation.

  EFI_STATUS                            LastWriteError;        // Most recent write error. Will cause dump to be marked invalid.
  UINT32                                CurrentBufferInfoUsed; // Bytes written to pCurrentBufferInfo's buffer.
  UINT64                                FlushedMediaPosition;  // MediaPosition = FlushedMediaPosition + CurrentBufferInfoUsed.

  // Each BufferInfo should be covered by exactly one of the following at all times:

  DUMP_WRITER_BUFFER_INFO               *pCurrentBufferInfo;       // Filled up to CurrentBufferInfoUsed.
  DUMP_WRITER_BUFFER_INFO               *pFirstFreeBufferInfo;     // Linked-list of empty buffer infos.
  UINT32 volatile                       BusyBufferInfos;           // Write operations in progress.
  DUMP_WRITER_BUFFER_INFO * volatile    pFirstCompletedBufferInfo; // Linked-list of completed buffer infos ready to be flushed into pFirstFreeBufferInfo.
};

struct DUMP_WRITER_BUFFER_INFO {
  DUMP_WRITER_BUFFER_INFO    *pNext;       // Linked-list entry. Set to Self if in-flight.
  DUMP_WRITER                *pDumpWriter; // Parent.
  UINT8                      *pBuffer;     // Size is pDumpWriter->BufferSize, which must be a multiple of BlockSize.
  EFI_BLOCK_IO2_TOKEN        Token;        // Invokes DumpWriterOperationComplete when the operation completes.
};

// Returns false for overflow.
static BOOLEAN
DW_CheckedAdd32 (
  IN OUT UINT32  *Accumulator,
  UINT32         Addend
  )
{
  *Accumulator += Addend;
  return *Accumulator >= Addend;
}

static void
DW_BufferListInterlockedPush (
  IN OUT DUMP_WRITER_BUFFER_INFO * volatile  *ppFirst,
  IN OUT DUMP_WRITER_BUFFER_INFO             *pItem
  )
{
  ASSERT (pItem->pNext == NULL);

  DUMP_WRITER_BUFFER_INFO  *pExpectedFirst = *ppFirst;
  for ( ;;) {
    pItem->pNext = pExpectedFirst;

    // Interlocked: *ppFirst = pItem;
    DUMP_WRITER_BUFFER_INFO * const  pActualFirst =
      InterlockedCompareExchangePointer (
                                         (void * volatile *)ppFirst,
                                         pExpectedFirst,
                                         pItem
                                         );
    if (pActualFirst == pExpectedFirst) {
      return;
    }

    pExpectedFirst = pActualFirst;
  }
}

static DUMP_WRITER_BUFFER_INFO *
DW_BufferListInterlockedFlush (
  IN OUT DUMP_WRITER_BUFFER_INFO * volatile  *ppFirst
  )
{
  DUMP_WRITER_BUFFER_INFO  *pExpectedFirst = *ppFirst;

  while (pExpectedFirst) {
    // Interlocked: *ppFirst = NULL;
    DUMP_WRITER_BUFFER_INFO * const  pActualFirst =
      InterlockedCompareExchangePointer (
                                         (void * volatile *)ppFirst,
                                         pExpectedFirst,
                                         NULL
                                         );
    if (pActualFirst == pExpectedFirst) {
      return pExpectedFirst;
    }

    pExpectedFirst = pActualFirst;
  }

  // Already NULL.
  return NULL;
}

static void EFIAPI
DW_BufferInfoOperationComplete (
  IN EFI_EVENT  Event,
  IN VOID       *pContext
  )
{
  DUMP_WRITER_BUFFER_INFO * const  pComplete = (DUMP_WRITER_BUFFER_INFO *)pContext;

  ASSERT (pComplete->pNext == pComplete); // In-flight.
  pComplete->pNext = NULL;

  // Move info from BusyBufferInfos to CompletedBufferInfos.
  // In theory, the callback can't be interrupted (runs at TPL_CALLBACK) so this doesn't
  // need to be interlocked. However, it does need to be interlocked on the other end.
  DUMP_WRITER * const  pDumpWriter = pComplete->pDumpWriter;
  DW_BufferListInterlockedPush (&pDumpWriter->pFirstCompletedBufferInfo, pComplete);
  UINT32  NewBusyCount = InterlockedDecrement (&pDumpWriter->BusyBufferInfos);
  DEBUG_PRINT (DEBUG_INFO, "PostDecrement BusyBufferInfos = %u\n", NewBusyCount);

  // Protected (runs at TPL_CALLBACK). If this were actually multi-threaded, the info
  // could be deleted between the InterlockedDecrement and the SignalEvent.
  DEBUG_PRINT (DEBUG_INFO, "Signal FreeBuffer for %p\n", pContext);
  gBS->SignalEvent (pDumpWriter->OperationCompleted);
}

static void
DW_BufferInfoDestruct (
  IN OUT DUMP_WRITER_BUFFER_INFO  *pBufferInfo
  )
{
  ASSERT (pBufferInfo->pNext != pBufferInfo); // Not in-flight.

  if (pBufferInfo->Token.Event) {
    gBS->CloseEvent (pBufferInfo->Token.Event);
    pBufferInfo->Token.Event = NULL;
  }

  if (pBufferInfo->pBuffer) {
    FreeAlignedPages (pBufferInfo->pBuffer, EFI_SIZE_TO_PAGES (pBufferInfo->pDumpWriter->BufferSize));
    pBufferInfo->pBuffer = NULL;
  }
}

static EFI_STATUS
DW_BufferInfoConstruct (
  IN DUMP_WRITER                  *pDumpWriter,
  IN UINT32                       MediaIoAlign,
  IN OUT DUMP_WRITER_BUFFER_INFO  *pBufferInfo
  )
{
  // Caller should allocate zeroed memory.
  ASSERT (pBufferInfo->pNext == NULL);
  ASSERT (pBufferInfo->pBuffer == NULL);
  ASSERT (pBufferInfo->Token.Event == NULL);

  pBufferInfo->pDumpWriter = pDumpWriter;

  pBufferInfo->pBuffer = AllocateAlignedPages (EFI_SIZE_TO_PAGES (pDumpWriter->BufferSize), MediaIoAlign);
  if (!pBufferInfo->pBuffer) {
    return EFI_OUT_OF_RESOURCES;
  }

  EFI_STATUS  Status;

  // Signal-type event - cannot wait on it, signal triggers callback.
  Status = gBS->CreateEvent (
                             EVT_NOTIFY_SIGNAL,
                             TPL_CALLBACK,
                             DW_BufferInfoOperationComplete,
                             pBufferInfo,
                             &pBufferInfo->Token.Event
                             );
  if (EFI_ERROR (Status)) {
    FreePool (pBufferInfo->pBuffer);
    pBufferInfo->pBuffer = NULL;
    return Status;
  }

  return EFI_SUCCESS;
}

static void
DW_PushFreeBuffer (
  IN OUT DUMP_WRITER              *pDumpWriter,
  IN OUT DUMP_WRITER_BUFFER_INFO  *pFreeItem
  )
{
  ASSERT (pFreeItem->pNext == NULL);
  ASSERT (pFreeItem->pDumpWriter == pDumpWriter);
  ASSERT (pFreeItem->pBuffer != NULL);
  ASSERT (pFreeItem->Token.Event != NULL);
  ASSERT (pFreeItem->Token.TransactionStatus == EFI_SUCCESS);
  pFreeItem->pNext                  = pDumpWriter->pFirstFreeBufferInfo;
  pDumpWriter->pFirstFreeBufferInfo = pFreeItem;
}

static void
DW_WaitForFreeBuffer (
  IN OUT DUMP_WRITER  *pDumpWriter
  )
{
  // Loop until we flush at least one buffer from completed list to free list.
  for ( ;;) {
    ASSERT (!pDumpWriter->pFirstFreeBufferInfo);

    // Flush the completed buffer list.
    DUMP_WRITER_BUFFER_INFO  *pFirstCompleted =
      DW_BufferListInterlockedFlush (&pDumpWriter->pFirstCompletedBufferInfo);
    if (pFirstCompleted) {
      // Flushed one or more buffers from completed buffer list.
      // Add them to the free list.
      do {
        DUMP_WRITER_BUFFER_INFO * const  pFreeItem = pFirstCompleted;
        pFirstCompleted  = pFreeItem->pNext;
        pFreeItem->pNext = NULL;

        if (EFI_ERROR (pFreeItem->Token.TransactionStatus)) {
          // Track failed write operation.
          pDumpWriter->LastWriteError = pFreeItem->Token.TransactionStatus;
        }

        pFreeItem->Token.TransactionStatus = EFI_SUCCESS;

        DW_PushFreeBuffer (pDumpWriter, pFreeItem);
      } while (pFirstCompleted);

      // Flushed something so we're done.
      return;
    }

    // No completed buffers. Wait for signal and try again.
    DEBUG_PRINT (DEBUG_INFO, "Wait FreeBuffer - begin\n");
    gBS->WaitForEvent (1, &pDumpWriter->OperationCompleted, NULL);
    DEBUG_PRINT (DEBUG_INFO, "Wait FreeBuffer - end\n");
  }
}

static DUMP_WRITER_BUFFER_INFO *
DW_GetFreeBuffer (
  IN OUT DUMP_WRITER  *pDumpWriter
  )
{
  DUMP_WRITER_BUFFER_INFO  *pFreeBuffer = pDumpWriter->pFirstFreeBufferInfo;

  if (!pFreeBuffer) {
    DW_WaitForFreeBuffer (pDumpWriter);
    pFreeBuffer = pDumpWriter->pFirstFreeBufferInfo;
  }

  pDumpWriter->pFirstFreeBufferInfo = pFreeBuffer->pNext;
  pFreeBuffer->pNext                = NULL;
  return pFreeBuffer;
}

static RAW_DUMP_HEADER *
DW_DumpHeader (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return (RAW_DUMP_HEADER *)(pDumpWriter->pHeaders + pDumpWriter->RawDumpOffset);
}

static RAW_DUMP_SECTION_HEADER *
DW_SectionHeaders (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return (RAW_DUMP_SECTION_HEADER *)(pDumpWriter->pHeaders + pDumpWriter->RawDumpOffset + sizeof (RAW_DUMP_HEADER));
}

static void
DW_CurrentBufferInfoFlush (
  IN OUT DUMP_WRITER  *pDumpWriter
  )
{
  if (pDumpWriter->MediaSize <= pDumpWriter->FlushedMediaPosition) {
    return;
  }

  UINT64 const  MediaRemaining = pDumpWriter->MediaSize - pDumpWriter->FlushedMediaPosition;

  DUMP_WRITER_BUFFER_INFO * const  pCurrentBufferInfo    = pDumpWriter->pCurrentBufferInfo;
  UINT32 const                     CurrentBufferInfoUsed = pDumpWriter->CurrentBufferInfoUsed;
  UINT32 const                     BytesToWrite          = (UINT32)MIN (MediaRemaining, CurrentBufferInfoUsed);
  UINT8 const                      MediaBlockShift       = pDumpWriter->MediaBlockShift;
  UINT8                            *pBuffer              = pCurrentBufferInfo->pBuffer;

  ASSERT (pCurrentBufferInfo);
  ASSERT (CurrentBufferInfoUsed != 0);
  ASSERT (CurrentBufferInfoUsed <= pDumpWriter->BufferSize);
  ASSERT (0 == (CurrentBufferInfoUsed & ((1u << MediaBlockShift) - 1)));
  ASSERT (BytesToWrite != 0);
  ASSERT (0 == (BytesToWrite & ((1u << MediaBlockShift) - 1)));
  ASSERT (0 == (pDumpWriter->FlushedMediaPosition & ((1u << MediaBlockShift) - 1)));

  EFI_STATUS  Status;

  if (pDumpWriter->pEncryptor) {
    DEBUG_PRINT (
                 DEBUG_INFO,
                 "Encrypting %u bytes using offset %llu (data)\n",
                 BytesToWrite,
                 pDumpWriter->FlushedMediaPosition - pDumpWriter->RawDumpOffset
                 );
    Status = EncryptorEncrypt (
                               pDumpWriter->pEncryptor,
                               pDumpWriter->FlushedMediaPosition - pDumpWriter->RawDumpOffset,
                               BytesToWrite,
                               pBuffer,
                               pBuffer
                               );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "EncryptorEncrypt (data) failed: %r\n", Status);
      pDumpWriter->LastWriteError = Status;
      ZeroMem (pBuffer, BytesToWrite);
    }
  }

  if (pDumpWriter->pBlockIo2) {
    // Send pCurrentBufferInfo into the void.
    pDumpWriter->pCurrentBufferInfo = NULL;
    pCurrentBufferInfo->pNext       = pCurrentBufferInfo; // In-flight
    UINT32  NewBusyCount = InterlockedIncrement (&pDumpWriter->BusyBufferInfos);
    DEBUG_PRINT (DEBUG_INFO, "PostIncrement BusyBufferInfos = %u\n", NewBusyCount);

    EFI_BLOCK_IO2_PROTOCOL * const  pBlockIo2 = pDumpWriter->pBlockIo2;
    Status = pBlockIo2->WriteBlocksEx (
                                       pBlockIo2,
                                       pDumpWriter->MediaID,
                                       pDumpWriter->FlushedMediaPosition >> MediaBlockShift,
                                       &pCurrentBufferInfo->Token,
                                       BytesToWrite,
                                       pBuffer
                                       );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "WriteBlocksEx failed: %r\n", Status);
      // Didn't queue a Write, so callback won't be invoked. Put it back.
      pDumpWriter->pCurrentBufferInfo = pCurrentBufferInfo;
      pCurrentBufferInfo->pNext       = NULL; // Not in-flight
      NewBusyCount                    = InterlockedDecrement (&pDumpWriter->BusyBufferInfos);
      DEBUG_PRINT (DEBUG_INFO, "PostDecrement BusyBufferInfos = %u\n", NewBusyCount);
      pDumpWriter->LastWriteError = Status;
    }
  } else {
    EFI_BLOCK_IO_PROTOCOL * const  pBlockIo = pDumpWriter->pBlockIo;
    Status = pBlockIo->WriteBlocks (
                                    pBlockIo,
                                    pDumpWriter->MediaID,
                                    pDumpWriter->FlushedMediaPosition >> MediaBlockShift,
                                    BytesToWrite,
                                    pBuffer
                                    );
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "WriteBlocks failed: %r\n", Status);
      pDumpWriter->LastWriteError = Status;
    }
  }

  pDumpWriter->FlushedMediaPosition += CurrentBufferInfoUsed;
  pDumpWriter->CurrentBufferInfoUsed = 0;
}

static void
DW_Delete (
  IN OUT DUMP_WRITER  *pDumpWriter
  )
{
  ASSERT (pDumpWriter->BusyBufferInfos == 0);

  EncryptorDelete (pDumpWriter->pEncryptor);
  pDumpWriter->pEncryptor = NULL;

  if (pDumpWriter->pHeaders) {
    FreeAlignedPages (pDumpWriter->pHeaders, EFI_SIZE_TO_PAGES (pDumpWriter->HeadersSize));
    pDumpWriter->pHeaders = NULL;
  }

  if (pDumpWriter->pHeadersSync) {
    FreeAlignedPages (pDumpWriter->pHeadersSync, EFI_SIZE_TO_PAGES (pDumpWriter->HeadersSyncSize));
    pDumpWriter->pHeadersSync = NULL;
  }

  if (pDumpWriter->pBufferInfos) {
    for (UINT32 i = 0; i != pDumpWriter->BufferCount; i += 1) {
      DW_BufferInfoDestruct (&pDumpWriter->pBufferInfos[i]);
    }

    FreePool (pDumpWriter->pBufferInfos);
    pDumpWriter->pBufferInfos = NULL;
  }

  gBS->CloseEvent (pDumpWriter->OperationCompleted);

  FreePool (pDumpWriter);
}

EFI_STATUS
DumpWriterClose (
  IN OUT DUMP_WRITER  *pDumpWriter,
  IN BOOLEAN          DumpValid
  )
{
  if (pDumpWriter->CurrentBufferInfoUsed != 0) {
    ASSERT (pDumpWriter->pCurrentBufferInfo);
    UINT32  TailSize = ALIGN_VALUE_ADDEND (pDumpWriter->CurrentBufferInfoUsed, 1u << pDumpWriter->MediaBlockShift);
    ZeroMem (
             pDumpWriter->pCurrentBufferInfo->pBuffer + pDumpWriter->CurrentBufferInfoUsed,
             TailSize
             );
    pDumpWriter->CurrentBufferInfoUsed += TailSize;
    DW_CurrentBufferInfoFlush (pDumpWriter);
  }

  // Wait for all pending operations to complete.
  // No more async after this point.
  while (pDumpWriter->BusyBufferInfos != 0) {
    DEBUG_PRINT (DEBUG_INFO, "Wait BusyBufferInfos %u - begin\n", pDumpWriter->BusyBufferInfos);
    gBS->WaitForEvent (1, &pDumpWriter->OperationCompleted, NULL);
    DEBUG_PRINT (DEBUG_INFO, "Wait BusyBufferInfos %u - end\n", pDumpWriter->BusyBufferInfos);
  }

  DEBUG_PRINT (
               DEBUG_INFO,
               "Close: LastError=%u MediaSize=%llu NeededSize=%llu\n",
               pDumpWriter->LastWriteError,
               DumpWriterMediaSize (pDumpWriter),
               DumpWriterMediaPosition (pDumpWriter)
               );

  RAW_DUMP_HEADER  *pDumpHeader = DW_DumpHeader (pDumpWriter);
  if (EFI_ERROR (pDumpWriter->LastWriteError)) {
    // Do not set any flags (dump invalid).
  } else if (DumpWriterHasInsufficientStorage (pDumpWriter)) {
    pDumpHeader->Flags |= RAW_DUMP_HEADER_INSUFFICIENT_STORAGE;
  } else if (DumpValid) {
    pDumpHeader->Flags |= RAW_DUMP_HEADER_DUMP_VALID;
  } else {
    // Do not set any flags (dump invalid).
  }

  // TODO: should we flush the headers once without the RAW_DUMP_HEADER_DUMP_VALID bit to
  // ensure headers are fully written, and then make a second write that updates just the
  // valid bit?
  EFI_STATUS  Status = DumpWriterFlushHeaders (pDumpWriter);

  if (!EFI_ERROR (Status)) {
    if (pDumpWriter->pBlockIo2) {
      Status = pDumpWriter->pBlockIo2->FlushBlocksEx (pDumpWriter->pBlockIo2, NULL);
    } else {
      Status = pDumpWriter->pBlockIo->FlushBlocks (pDumpWriter->pBlockIo);
    }
  }

  DW_Delete (pDumpWriter);
  return Status;
}

EFI_STATUS
DumpWriterOpen (
  IN EFI_HANDLE                 DumpDeviceHandle,
  IN RAW_DUMP_HEADER_FLAGS      DumpHeaderFlags,
  IN UINT32                     SectionCountExpected,
  IN DUMP_WRITER_OPTIONS const  *pOptions,
  OUT DUMP_WRITER               **ppDumpWriter
  )
{
  static const RAW_DUMP_HEADER_FLAGS  RawDumpHeaderInvalidFlags =
    RAW_DUMP_HEADER_DUMP_VALID |
    RAW_DUMP_HEADER_INSUFFICIENT_STORAGE;

  if (!DumpDeviceHandle ||
      (0 != (DumpHeaderFlags & RawDumpHeaderInvalidFlags)) ||
      (SectionCountExpected > SectionCountMax) ||
      !ppDumpWriter)
  {
    return EFI_INVALID_PARAMETER;
  }

  EFI_STATUS         Status;
  DUMP_WRITER        *pDumpWriter;
  ENC_DUMP_KEY_INFO  *pKeyInfo = NULL;
  UINT32             MediaIoAlign;

  // pDumpWriter, SectionCountExpected, OperationCompleted
  {
    pDumpWriter = AllocateZeroPool (sizeof (*pDumpWriter));
    if (!pDumpWriter) {
      DEBUG_PRINT (DEBUG_ERROR, "Failed to allocate memory for DUMP_WRITER\n");
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    pDumpWriter->SectionCountExpected = SectionCountExpected;

    // Simple event - can wait on it, signal unblocks wait, no callback.
    Status = gBS->CreateEvent (0, 0, NULL, NULL, &pDumpWriter->OperationCompleted);
    if (EFI_ERROR (Status)) {
      DEBUG_PRINT (DEBUG_ERROR, "Failed %r to CreateEvent for OperationCompleted\n", Status);
      goto Done;
    }
  }

  // pKeyInfo, pEncryptor
  {
    ENC_DUMP_ALGORITHM  EncDumpAlgorithm;

    if (pOptions && pOptions->ForceUnencrypted) {
      EncDumpAlgorithm = ENC_DUMP_ALGORITHM_NONE;
    } else {
      Status = OfflineMemoryDumpEncryptionAlgorithm (&EncDumpAlgorithm);
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "Failed %r to read EncryptionAlgorithm\n", Status);
        goto Done;
      }
    }

    if (EncDumpAlgorithm != ENC_DUMP_ALGORITHM_NONE) {
      void    *pRecipientCertificate   = NULL;
      UINT32  RecipientCertificateSize = 0;
      Status = OfflineMemoryDumpEncryptionPublicKey (&pRecipientCertificate, &RecipientCertificateSize);
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "Failed %r to read PublicKey\n", Status);
        goto Done;
      }

      Status = EncryptorNewKeyInfoBlock (
                                         EncDumpAlgorithm,
                                         pRecipientCertificate,
                                         RecipientCertificateSize,
                                         &pDumpWriter->pEncryptor,
                                         &pKeyInfo
                                         );
      FreePool (pRecipientCertificate);

      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "Failed %r EncryptorNewKeyInfoBlock\n", Status);
        goto Done;
      }

      ASSERT (pDumpWriter->pEncryptor);
      ASSERT (pKeyInfo);
    }
  }

  // pBlockIo2, pBlockIo, MediaID, MediaBlockShift, MediaSize, MediaIoAlign
  {
    EFI_BLOCK_IO_MEDIA const  *pMedia;

    if (pOptions && pOptions->DisableBlockIo2) {
      Status = EFI_UNSUPPORTED;
    } else {
      Status = gBS->OpenProtocol (
                                  DumpDeviceHandle,
                                  &gEfiBlockIo2ProtocolGuid,
                                  (VOID **)&pDumpWriter->pBlockIo2,
                                  gImageHandle,
                                  NULL,
                                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                  );
    }

    if (!EFI_ERROR (Status)) {
      pMedia = pDumpWriter->pBlockIo2->Media;
    } else {
      Status = gBS->OpenProtocol (
                                  DumpDeviceHandle,
                                  &gEfiBlockIoProtocolGuid,
                                  (VOID **)&pDumpWriter->pBlockIo,
                                  gImageHandle,
                                  NULL,
                                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                                  );
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "Failed %r OpenProtocol(BlockIo)\n", Status);
        goto Done;
      }

      pMedia = pDumpWriter->pBlockIo->Media;
    }

    // Sanity-check the block size: 512 or larger, and a power of 2.
    if ((pMedia->BlockSize < 512) || ((pMedia->BlockSize & (pMedia->BlockSize - 1)) != 0)) {
      DEBUG_PRINT (DEBUG_ERROR, "Bad block size %u\n", pMedia->BlockSize);
      Status = EFI_UNSUPPORTED;
      goto Done;
    }

    UINT64 const   LastBlockMax   = MAX_UINT64 / pMedia->BlockSize - 1;
    EFI_LBA const  MediaLastBlock = MIN (pMedia->LastBlock, LastBlockMax);

    pDumpWriter->MediaID         = pMedia->MediaId;
    pDumpWriter->MediaBlockShift = (UINT8)HighBitSet32 (pMedia->BlockSize);
    ASSERT (pMedia->BlockSize == 1u << pDumpWriter->MediaBlockShift);
    pDumpWriter->MediaSize = (MediaLastBlock + 1) * pMedia->BlockSize;
    MediaIoAlign           = pMedia->IoAlign;
  }

  UINT32 const  BufferAlignment = MAX (EFI_PAGE_SIZE, 1u << pDumpWriter->MediaBlockShift);
  DEBUG_PRINT (DEBUG_INFO, "BufferAlignment: %u\n", BufferAlignment);

  // pHeaders, HeadersSize, RawDumpOffset, FlushedMediaPosition
  {
    UINT32        HeadersSize             = 0;
    UINT32        EncHeaderPadding        = 0;
    UINT32 const  SectionHeadersByteCount = SectionCountExpected * (UINT32)sizeof (RAW_DUMP_SECTION_HEADER);

    if (pKeyInfo) {
      HeadersSize += sizeof (ENC_DUMP_HEADER);

      if (!DW_CheckedAdd32 (&HeadersSize, pKeyInfo->BlockSize)) {
        DEBUG_PRINT (DEBUG_ERROR, "HeadersSize overflow pKeyInfo->BlockSize\n");
        Status = EFI_BAD_BUFFER_SIZE;
        goto Done;
      }

      EncHeaderPadding = ALIGN_VALUE_ADDEND (HeadersSize, SectionAlign);
      if (!DW_CheckedAdd32 (&HeadersSize, EncHeaderPadding)) {
        DEBUG_PRINT (DEBUG_ERROR, "HeadersSize overflow EncHeaderPadding\n");
        Status = EFI_BAD_BUFFER_SIZE;
        goto Done;
      }
    }

    pDumpWriter->RawDumpOffset = HeadersSize;
    ASSERT (pDumpWriter->RawDumpOffset % SectionAlign == 0);

    if (!DW_CheckedAdd32 (&HeadersSize, sizeof (RAW_DUMP_HEADER))) {
      DEBUG_PRINT (DEBUG_ERROR, "HeadersSize overflow RAW_DUMP_HEADER\n");
      Status = EFI_BAD_BUFFER_SIZE;
      goto Done;
    }

    if (!DW_CheckedAdd32 (&HeadersSize, SectionHeadersByteCount)) {
      DEBUG_PRINT (DEBUG_ERROR, "HeadersSize overflow SectionHEadersByteCount %u\n", SectionHeadersByteCount);
      Status = EFI_BAD_BUFFER_SIZE;
      goto Done;
    }

    if (!DW_CheckedAdd32 (&HeadersSize, ALIGN_VALUE_ADDEND (HeadersSize, BufferAlignment))) {
      DEBUG_PRINT (DEBUG_ERROR, "HeadersSize overflow Alignment %u\n", ALIGN_VALUE_ADDEND (HeadersSize, BufferAlignment));
      Status = EFI_BAD_BUFFER_SIZE;
      goto Done;
    }

    if (pDumpWriter->MediaSize < HeadersSize) {
      DEBUG_PRINT (DEBUG_ERROR, "HeaderSize %u doesn't fit in MediaSize %llu\n", HeadersSize, pDumpWriter->MediaSize);
      Status = EFI_VOLUME_FULL;
      goto Done;
    }

    UINT8 * const  pHeaders = AllocateAlignedPages (EFI_SIZE_TO_PAGES (HeadersSize), MediaIoAlign);
    if (!pHeaders) {
      DEBUG_PRINT (
                   DEBUG_ERROR,
                   "Failed to allocate %u headers pages at alignment %u\n",
                   EFI_SIZE_TO_PAGES (HeadersSize),
                   MediaIoAlign
                   );
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    DEBUG_PRINT (DEBUG_INFO, "HeadersSize: %u\n", HeadersSize);
    ZeroMem (pHeaders, HeadersSize);

    pDumpWriter->pHeaders             = pHeaders;
    pDumpWriter->HeadersSize          = HeadersSize;
    pDumpWriter->FlushedMediaPosition = HeadersSize;

    UINT8  *pHeadersPos = pHeaders;

    if (pKeyInfo) {
      *(ENC_DUMP_HEADER *)pHeadersPos = (ENC_DUMP_HEADER) {
        .Signature     = ENC_DUMP_HEADER_SIGNATURE,
        .HeaderSize    = sizeof (ENC_DUMP_HEADER),
        .KeyInfoOffset = sizeof (ENC_DUMP_HEADER),
        .RawDumpOffset = pDumpWriter->RawDumpOffset,
      };
      pHeadersPos += sizeof (ENC_DUMP_HEADER);

      CopyMem (pHeadersPos, pKeyInfo, pKeyInfo->BlockSize);
      pHeadersPos += pKeyInfo->BlockSize;
      pHeadersPos += EncHeaderPadding;
    }

    RAW_DUMP_HEADER  *pDumpHeader = (RAW_DUMP_HEADER *)pHeadersPos;
    *pDumpHeader = (RAW_DUMP_HEADER) {
      .Signature             = RAW_DUMP_HEADER_SIGNATURE,
      .MajorVersion          = 1,
      .MinorVersion          = 0,
      .Flags                 = DumpHeaderFlags,
      .OsData                = 0,
      .CpuContext            = 0,
      .ResetTrigger          = 0,
      .DumpSize              = HeadersSize - pDumpWriter->RawDumpOffset,
      .TotalDumpSizeRequired = HeadersSize,
      .SectionsCount         = 0,
    };
    (void)OfflineMemoryDumpOsData (&pDumpHeader->OsData);

    pHeadersPos += sizeof (RAW_DUMP_HEADER);
    pHeadersPos += SectionHeadersByteCount;
    ASSERT (pHeadersPos <= pHeaders + HeadersSize);
  }

  // BufferSize, BufferCount, pBufferInfos, pFirstFreeBufferInfo
  {
    UINT8 const  BufferCount =
      !pDumpWriter->pBlockIo2
      ? 1 // No async support, use one large block.
      : pOptions && pOptions->BufferCount != 0
      ? MAX (pOptions->BufferCount, 2) // Count specified, use it. Must be at least 2.
      : BufferCountDefault;            // Count not specified, default.
    UINT32 const  BufferMemoryLimit =
      pOptions && pOptions->BufferMemoryLimit != 0
      ? MIN (pOptions->BufferMemoryLimit, MAX_UINT32 - BufferAlignment) // Limit specified, use it.
      : BufferMemoryLimitDefault;                                       // Limit not specified, default.

    UINT32  ProposedBufferSize = BufferMemoryLimit / BufferCount;
    if (!pDumpWriter->pBlockIo2) {
      // Special case: Device only supports blocking I/O so we want to prioritize one
      // large I/O buffer, but we need a second I/O buffer to use for
      // DumpWriterFlushHeaders when the large buffer is partially filled. In this case,
      // allocate a dedicated buffer for DumpWriterFlushHeaders.
      UINT32 const  HeadersSyncSize =
        pDumpWriter->HeadersSize <= ProposedBufferSize / 2
        ? pDumpWriter->HeadersSize
        : ALIGN_VALUE (pDumpWriter->RawDumpOffset + 1, BufferAlignment);

      // Adjust the size of the primary I/O buffer down a bit to account for the dedicated buffer.
      ProposedBufferSize =
        HeadersSyncSize <= ProposedBufferSize / 2
        ? ProposedBufferSize - HeadersSyncSize
        : ProposedBufferSize / 2;

      pDumpWriter->pHeadersSync = AllocateAlignedPages (EFI_SIZE_TO_PAGES (HeadersSyncSize), MediaIoAlign);
      if (!pDumpWriter->pHeadersSync) {
        DEBUG_PRINT (
                     DEBUG_ERROR,
                     "Failed to allocate %u headersSync pages at alignment %u\n",
                     EFI_SIZE_TO_PAGES (HeadersSyncSize),
                     MediaIoAlign
                     );
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
      }

      ZeroMem (pDumpWriter->pHeadersSync, HeadersSyncSize);
      pDumpWriter->HeadersSyncSize = HeadersSyncSize;
    }

    UINT32 const  BufferSize =
      ProposedBufferSize < BufferAlignment
      ? BufferAlignment                              // Proposed size too small. Use block size.
      : ProposedBufferSize & ~(BufferAlignment - 1); // Proposed size ok, round down to block size.

    DEBUG_PRINT (DEBUG_INFO, "BufferSize: %uKB\n", BufferSize / 1024);
    DEBUG_PRINT (DEBUG_INFO, "BufferCount: %u\n", BufferCount);

    pDumpWriter->BufferSize   = BufferSize;
    pDumpWriter->BufferCount  = BufferCount;
    pDumpWriter->pBufferInfos = AllocateZeroPool (BufferCount * sizeof (DUMP_WRITER_BUFFER_INFO));
    if (!pDumpWriter->pBufferInfos) {
      DEBUG_PRINT (
                   DEBUG_ERROR,
                   "Failed to allocate %u BufferInfo bytes\n",
                   BufferCount * sizeof (DUMP_WRITER_BUFFER_INFO)
                   );
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    for (unsigned i = 0; i != BufferCount; i += 1) {
      DUMP_WRITER_BUFFER_INFO * const  pInfo = &pDumpWriter->pBufferInfos[i];
      Status = DW_BufferInfoConstruct (pDumpWriter, MediaIoAlign, pInfo);
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "Failed %r constructing BufferInfo %u\n", Status, i);
        goto Done;
      }

      DW_PushFreeBuffer (pDumpWriter, pInfo);
    }
  }

  Status = DumpWriterFlushHeaders (pDumpWriter);

Done:

  if (pKeyInfo) {
    FreePool (pKeyInfo);
  }

  if (EFI_ERROR (Status) && pDumpWriter) {
    DW_Delete (pDumpWriter);
    pDumpWriter = NULL;
  }

  *ppDumpWriter = pDumpWriter;
  return Status;
}

EFI_STATUS
DumpWriterLastWriteError (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return pDumpWriter->LastWriteError;
}

UINT64
DumpWriterMediaPosition (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return pDumpWriter->FlushedMediaPosition + pDumpWriter->CurrentBufferInfoUsed;
}

UINT64
DumpWriterMediaSize (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return pDumpWriter->MediaSize;
}

BOOLEAN
DumpWriterHasInsufficientStorage (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return DumpWriterMediaSize (pDumpWriter) < DumpWriterMediaPosition (pDumpWriter);
}

RAW_DUMP_HEADER const *
DumpWriterGetDumpHeader (
  IN DUMP_WRITER const  *pDumpWriter
  )
{
  return DW_DumpHeader (pDumpWriter);
}

EFI_STATUS
DumpWriterFlushHeaders (
  IN OUT DUMP_WRITER  *pDumpWriter
  )
{
  // Note: DumpWriterClose assumes that this does not launch any async operations.

  EFI_STATUS                      Status;
  EFI_BLOCK_IO2_PROTOCOL * const  pBlockIo2       = pDumpWriter->pBlockIo2;
  EFI_BLOCK_IO_PROTOCOL * const   pBlockIo        = pDumpWriter->pBlockIo;
  UINT32 const                    MediaID         = pDumpWriter->MediaID;
  UINT8 const                     MediaBlockShift = pDumpWriter->MediaBlockShift;

  DUMP_WRITER_BUFFER_INFO  *pBufferInfo;
  UINT8                    *pDest;
  UINT32                   DestSize;

  if (pBlockIo2) {
    // Async I/O means there's at least 2 buffers.
    // 1 may be partially-filled, so we can't use it.
    // At least one will be free or in-flight (which we will wait for).
    ASSERT (!pDumpWriter->pHeadersSync);
    ASSERT (pDumpWriter->HeadersSyncSize == 0);
    pBufferInfo = DW_GetFreeBuffer (pDumpWriter);
    pDest       = pBufferInfo->pBuffer;
    DestSize    = pDumpWriter->BufferSize;
  } else {
    // Sync I/O means there's only 1 big buffer.
    // It may be partially-filled, so we can't use it.
    // We reserved a smaller buffer to handle this case.
    ASSERT (pDumpWriter->pHeadersSync);
    ASSERT (pDumpWriter->HeadersSyncSize >= EFI_PAGE_SIZE);
    pBufferInfo = NULL;
    pDest       = pDumpWriter->pHeadersSync;
    DestSize    = pDumpWriter->HeadersSyncSize;
  }

  UINT32 const  HeadersSize = pDumpWriter->HeadersSize;
  UINT32        Pos         = 0;
  while (Pos < HeadersSize) {
    UINT32 const  ThisBlockSize = MIN (DestSize, HeadersSize - Pos);
    UINT32 const  EndPos        = Pos + ThisBlockSize;
    CopyMem (pDest, &pDumpWriter->pHeaders[Pos], ThisBlockSize);

    if (pDumpWriter->pEncryptor && (EndPos > pDumpWriter->RawDumpOffset)) {
      UINT32 const  EncryptStart =
        Pos < pDumpWriter->RawDumpOffset
        ? pDumpWriter->RawDumpOffset - Pos
        : 0;
      DEBUG_PRINT (
                   DEBUG_INFO,
                   "Encrypting %u bytes using offset %llu (headers)\n",
                   ThisBlockSize - EncryptStart,
                   Pos + EncryptStart - pDumpWriter->RawDumpOffset
                   );
      Status = EncryptorEncrypt (
                                 pDumpWriter->pEncryptor,
                                 Pos + EncryptStart - pDumpWriter->RawDumpOffset,
                                 ThisBlockSize - EncryptStart,
                                 pDest + EncryptStart,
                                 pDest + EncryptStart
                                 );
      if (EFI_ERROR (Status)) {
        DEBUG_PRINT (DEBUG_ERROR, "EncryptorEncrypt (headers) failed: %r\n", Status);
        break;
      }
    }

    if (pBlockIo2) {
      Status = pBlockIo2->WriteBlocksEx (pBlockIo2, MediaID, Pos >> MediaBlockShift, NULL, ThisBlockSize, pDest);
    } else {
      Status = pBlockIo->WriteBlocks (pBlockIo, MediaID, Pos >> MediaBlockShift, ThisBlockSize, pDest);
    }

    if (EFI_ERROR (Status)) {
      break;
    }

    Pos += ThisBlockSize;
  }

  // Return the async buffer if we used it.
  if (pBufferInfo) {
    DW_PushFreeBuffer (pDumpWriter, pBufferInfo);
  }

  return Status;
}

EFI_STATUS
DumpWriterWriteSection (
  IN OUT DUMP_WRITER                     *pDumpWriter,
  IN RAW_DUMP_SECTION_HEADER_FLAGS       SectionHeaderFlags,
  IN UINT16                              MajorVersion,
  IN UINT16                              MinorVersion,
  IN RAW_DUMP_SECTION_TYPE               Type,
  IN RAW_DUMP_SECTION_INFORMATION const  *pInformation,
  IN CHAR8 const                         *pName,
  IN DUMP_WRITER_COPY_CALLBACK           *pDataCallback OPTIONAL,
  IN void const                          *pDataStart,
  IN UINTN                               DataSize
  )
{
  static const RAW_DUMP_SECTION_HEADER_FLAGS  RawDumpSectionHeaderInvalidFlags =
    RAW_DUMP_SECTION_HEADER_INSUFFICIENT_STORAGE;

  RAW_DUMP_HEADER * const  pDumpHeader   = DW_DumpHeader (pDumpWriter);
  UINT32 const             SectionsCount = pDumpHeader->SectionsCount;

  ASSERT (pDumpHeader->TotalDumpSizeRequired == DumpWriterMediaPosition (pDumpWriter));

  if ((0 != (SectionHeaderFlags & RawDumpSectionHeaderInvalidFlags)) ||
      !pInformation ||
      !pName ||
      ((DataSize != 0) && !pDataStart && !pDataCallback))
  {
    return EFI_INVALID_PARAMETER;
  } else if (SectionsCount >= pDumpWriter->SectionCountExpected) {
    ASSERT (SectionsCount == pDumpWriter->SectionCountExpected);
    return EFI_BUFFER_TOO_SMALL;
  }

  RAW_DUMP_SECTION_HEADER * const  pSectionHeader = DW_SectionHeaders (pDumpWriter) + SectionsCount;
  *pSectionHeader = (RAW_DUMP_SECTION_HEADER) {
    .Flags        = SectionHeaderFlags & ~RAW_DUMP_SECTION_HEADER_DUMP_VALID,
    .MajorVersion = MajorVersion,
    .MinorVersion = MinorVersion,
    .Type         = Type,
    .Offset       = DumpWriterMediaPosition (pDumpWriter) - pDumpWriter->RawDumpOffset,
    .Size         = 0,
    .Information  = *pInformation,
    .Name         = { 0 }
  };

  // Copy pName into pSectionHeader->Name, truncating if necessary.
  UINTN const  NameLen = AsciiStrnSizeS (pName, sizeof (pSectionHeader->Name) - 1);
  ASSERT (NameLen <= sizeof (pSectionHeader->Name));
  CopyMem (pSectionHeader->Name, pName, NameLen); // May not be null-terminated.

  // Current buffer should not be full -- it should be flushed when it becomes full.
  ASSERT (pDumpWriter->BufferSize > pDumpWriter->CurrentBufferInfoUsed);

  BOOLEAN  SectionValid = 0 != (SectionHeaderFlags & RAW_DUMP_SECTION_HEADER_DUMP_VALID);
  UINTN    Pos          = 0;
  while (DataSize > Pos) {
    ASSERT (Pos % 16 == 0);

    if (!pDumpWriter->pCurrentBufferInfo) {
      ASSERT (pDumpWriter->CurrentBufferInfoUsed == 0);
      pDumpWriter->pCurrentBufferInfo = DW_GetFreeBuffer (pDumpWriter);
    }

    UINTN const   Remaining = DataSize - Pos;
    UINT32 const  Capacity  = pDumpWriter->BufferSize - pDumpWriter->CurrentBufferInfoUsed;
    UINT32 const  ToCopy    = (UINT32)MIN (Capacity, Remaining);

    UINT8 * const  DestinationPos = pDumpWriter->pCurrentBufferInfo->pBuffer + pDumpWriter->CurrentBufferInfoUsed;
    if (!pDataCallback) {
      // TODO: Optimize this -- we can probably avoid the CopyMem and do the copy as part of the
      // encryption operation.
      CopyMem (
               DestinationPos,
               (UINT8 const *)pDataStart + Pos,
               ToCopy
               );
    } else {
      EFI_STATUS  Status;
      Status = pDataCallback (DestinationPos, pDataStart, Pos, ToCopy);
      if (EFI_ERROR (Status)) {
        SectionValid                = FALSE;
        pDumpWriter->LastWriteError = Status;
        break;
      }
    }

    pDumpWriter->CurrentBufferInfoUsed += ToCopy;

    if (pDumpWriter->CurrentBufferInfoUsed >= pDumpWriter->BufferSize) {
      ASSERT (pDumpWriter->CurrentBufferInfoUsed == pDumpWriter->BufferSize);
      DW_CurrentBufferInfoFlush (pDumpWriter);
    }

    Pos += ToCopy;
  }

  ASSERT (Pos == DataSize || !SectionValid);
  pSectionHeader->Size = Pos;

  if (DumpWriterHasInsufficientStorage (pDumpWriter)) {
    pSectionHeader->Flags |= RAW_DUMP_SECTION_HEADER_INSUFFICIENT_STORAGE;
  } else if (SectionValid) {
    pSectionHeader->Flags |= RAW_DUMP_SECTION_HEADER_DUMP_VALID;
  }

  ASSERT (pSectionHeader->Size == DumpWriterMediaPosition (pDumpWriter) - pDumpWriter->RawDumpOffset - pSectionHeader->Offset);

  // Start next section on a 16-byte boundary.
  UINT32 const  PaddingSize = ALIGN_VALUE_ADDEND (pDumpWriter->CurrentBufferInfoUsed, SectionAlign);
  if (PaddingSize != 0) {
    ZeroMem (
             pDumpWriter->pCurrentBufferInfo->pBuffer + pDumpWriter->CurrentBufferInfoUsed,
             PaddingSize
             );
    pDumpWriter->CurrentBufferInfoUsed += PaddingSize;

    if (pDumpWriter->CurrentBufferInfoUsed >= pDumpWriter->BufferSize) {
      ASSERT (pDumpWriter->CurrentBufferInfoUsed == pDumpWriter->BufferSize);
      DW_CurrentBufferInfoFlush (pDumpWriter);
    }
  }

  pDumpHeader->TotalDumpSizeRequired = DumpWriterMediaPosition (pDumpWriter);
  pDumpHeader->DumpSize              =
    MIN (pDumpHeader->TotalDumpSizeRequired, pDumpWriter->MediaSize) - pDumpWriter->RawDumpOffset;
  pDumpHeader->SectionsCount = SectionsCount + 1;

  return EFI_SUCCESS;
}
