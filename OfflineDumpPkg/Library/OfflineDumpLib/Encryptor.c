#include <Library/OfflineDumpEncryptor.h>

typedef struct {
  UINT64    Lo;
  UINT64    Hi;
} AES_BLOCK;

STATIC_ASSERT (
               sizeof (AES_BLOCK) == 16,
               "AES_BLOCK expected to be 16 bytes"
               );

// Temporary to be fixed: Reach directly into OpensslLib's headers for
// functionality that is not yet supported by BaseCryptLib.
#undef _WIN32
#undef _WIN64
#include <Library/Include/CrtLibSupport.h>  // CryptoPkg/...
#include <openssl/evp.h>                    // CryptoPkg/Library/OpensslLib/openssl/include/...
#include <openssl/x509.h>                   // CryptoPkg/Library/OpensslLib/openssl/include/...
#include <openssl/pkcs7.h>                  // CryptoPkg/Library/OpensslLib/openssl/include/...

#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>

/*
Almost-useful functions from BaseCryptLib.h:

- AesInit
- AesCbcEncrypt
- RsaGetPublicKeyFromX509, RsaFree
- X509ConstructCertificate, X509Free
- X509Get***
- RsaOaepEncrypt
- RandomBytes

To be able to use BaseCryptLib.h instead of <openssl/???.h>, we need:

- AesEcbEncrypt (with ASM optimizations)
- Pkcs7Encrypt
*/

enum {
  AES_BLOCK_MASK                = AES_BLOCK_SIZE - 1,
  KEY_STREAM_BUFFER_SIZE        = 4096,
  KEY_STREAM_BUFFER_BLOCK_COUNT = KEY_STREAM_BUFFER_SIZE / sizeof (AES_BLOCK)
};

STATIC_ASSERT (
               KEY_STREAM_BUFFER_SIZE == KEY_STREAM_BUFFER_BLOCK_COUNT * sizeof (AES_BLOCK),
               "KeyStreamBufferSize must be a multiple of 16"
               );

struct OFFLINE_DUMP_ENCRYPTOR {
  EVP_CIPHER_CTX    *pCipherCtx;
  UINT8             Aes128Key[16];
  UINT64            InitializationVector;
  AES_BLOCK         KeyStreamBuffer[KEY_STREAM_BUFFER_BLOCK_COUNT];
};

void
OfflineDumpEncryptorDelete (
  IN OUT OFFLINE_DUMP_ENCRYPTOR  *pEncryptor
  )
{
  if (NULL != pEncryptor) {
    EVP_CIPHER_CTX_free (pEncryptor->pCipherCtx);
    ZeroMem (pEncryptor, OFFSET_OF (OFFLINE_DUMP_ENCRYPTOR, KeyStreamBuffer));
    FreePool (pEncryptor);
  }
}

EFI_STATUS
OfflineDumpEncryptorNewAes128Ctr (
  IN UINT8 const              Key[16],
  IN UINT64                   IV,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor
  )
{
  ASSERT (Key != NULL);
  ASSERT (ppEncryptor != NULL);

  *ppEncryptor = NULL;

  OFFLINE_DUMP_ENCRYPTOR  *pNewEncryptor = AllocatePool (sizeof (*pNewEncryptor));

  if (pNewEncryptor == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  pNewEncryptor->pCipherCtx = EVP_CIPHER_CTX_new ();
  if (pNewEncryptor->pCipherCtx == NULL) {
    FreePool (pNewEncryptor);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!EVP_EncryptInit (pNewEncryptor->pCipherCtx, EVP_aes_128_ecb (), Key, NULL) ||
      !EVP_CIPHER_CTX_set_padding (pNewEncryptor->pCipherCtx, 0))
  {
    OfflineDumpEncryptorDelete (pNewEncryptor);
    return EFI_DEVICE_ERROR;
  }

  CopyMem (pNewEncryptor->Aes128Key, Key, sizeof (pNewEncryptor->Aes128Key));
  pNewEncryptor->InitializationVector = IV;

  *ppEncryptor = pNewEncryptor;
  return EFI_SUCCESS;
}

EFI_STATUS
OfflineDumpEncryptorNewAes128CtrRandom (
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor
  )
{
  ASSERT (ppEncryptor != NULL);

  struct {
    UINT64    InitializationVector;
    UINT8     Aes128Key[16];
  } RandomData;

  if (!RandomBytes ((UINT8 *)&RandomData, sizeof (RandomData))) {
    *ppEncryptor = NULL;
    return EFI_DEVICE_ERROR;
  }

  EFI_STATUS  Status;

  Status = OfflineDumpEncryptorNewAes128Ctr (
                                             RandomData.Aes128Key,
                                             RandomData.InitializationVector,
                                             ppEncryptor
                                             );
  ZeroMem (&RandomData, sizeof (RandomData));
  return Status;
}

static BOOLEAN
OD_EncryptKeyStreamBuffer (
  IN OFFLINE_DUMP_ENCRYPTOR  *pEncryptor,
  IN UINT32                  BlockCount
  )
{
  int      InLen  = BlockCount * sizeof (AES_BLOCK);
  int      OutLen = 0;
  BOOLEAN  Ok;

  Ok = 0 != EVP_EncryptUpdate (
                               pEncryptor->pCipherCtx,
                               (UINT8 *)pEncryptor->KeyStreamBuffer,
                               &OutLen,
                               (UINT8 *)pEncryptor->KeyStreamBuffer,
                               InLen
                               );

  ASSERT (InLen == OutLen || !Ok);
  return Ok;
}

EFI_STATUS
OfflineDumpEncryptorEncrypt (
  IN OFFLINE_DUMP_ENCRYPTOR  *pEncryptor,
  IN UINT64                  StartingByteOffset,
  IN UINT32                  DataSize,
  IN void const              *pInputData,
  OUT void                   *pOutputData
  )
{
  ASSERT (pEncryptor != NULL);
  ASSERT (pInputData != NULL || DataSize == 0);
  ASSERT (pOutputData != NULL || DataSize == 0);

  UINT8 const  *pInputBytes  = pInputData;
  UINT8        *pOutputBytes = pOutputData;

  UINT64     StartingBlockIndex;
  AES_BLOCK  *pInputBlocks;
  AES_BLOCK  *pOutputBlocks;
  UINT32     DataBlockCount;

  if ((0 == (StartingByteOffset & AES_BLOCK_MASK)) &&
      (0 == (DataSize & AES_BLOCK_MASK)))
  {
    // Simple case: Data is aligned to AesBlock boundaries.
    StartingBlockIndex = StartingByteOffset / AES_BLOCK_SIZE;
    pInputBlocks       = (AES_BLOCK *)pInputBytes;
    pOutputBlocks      = (AES_BLOCK *)pOutputBytes;
    DataBlockCount     = DataSize / AES_BLOCK_SIZE;
  } else {
    // TBD: Do we ever need unaligned data?

    // Complex case: Partial block at start and/or end.
    UINT32 const  PrefixOffset    = (UINT32)StartingByteOffset & AES_BLOCK_MASK;
    UINT32 const  PrefixMax       = (AES_BLOCK_SIZE - PrefixOffset) & AES_BLOCK_MASK;
    UINT32 const  PrefixSize      = MIN (DataSize, PrefixMax);
    UINT32 const  DataAfterPrefix = DataSize - PrefixSize;
    UINT32 const  SuffixSize      = DataAfterPrefix & AES_BLOCK_MASK;

    StartingBlockIndex = StartingByteOffset / AES_BLOCK_SIZE + (PrefixSize != 0);
    pInputBlocks       = (AES_BLOCK *)(pInputBytes + PrefixSize);
    pOutputBlocks      = (AES_BLOCK *)(pOutputBytes + PrefixSize);
    DataBlockCount     = DataAfterPrefix / AES_BLOCK_SIZE;

    // Prefix CTR
    pEncryptor->KeyStreamBuffer[0].Lo = StartingBlockIndex - 1;
    pEncryptor->KeyStreamBuffer[0].Hi = pEncryptor->InitializationVector;

    // Suffix CTR
    pEncryptor->KeyStreamBuffer[1].Lo = StartingBlockIndex + DataBlockCount;
    pEncryptor->KeyStreamBuffer[1].Hi = pEncryptor->InitializationVector;

    if (!OD_EncryptKeyStreamBuffer (pEncryptor, 2)) {
      return EFI_DEVICE_ERROR;
    }

    // Handle the prefix (if any).
    for (UINT32 i = 0; i != PrefixSize; i += 1) {
      pOutputBytes[i] = pInputBytes[i] ^
                        ((UINT8 const *)&pEncryptor->KeyStreamBuffer[0])[PrefixOffset + i];
    }

    // Handle the suffix (if any).
    for (UINT32 i = 0; i != SuffixSize; i += 1) {
      UINT32 const  BufferPos = DataSize - SuffixSize + i;
      pOutputBytes[BufferPos] = pInputBytes[BufferPos] ^
                                ((UINT8 const *)&pEncryptor->KeyStreamBuffer[1])[i];
    }
  }

  UINT32  ProcessedBlockCount = 0;

  while (DataBlockCount - ProcessedBlockCount >= KEY_STREAM_BUFFER_BLOCK_COUNT) {
    // Encrypt AES blocks in KeyStreamBlockCount-sized chunks.

    for (unsigned i = 0; i != KEY_STREAM_BUFFER_BLOCK_COUNT; i += 1) {
      pEncryptor->KeyStreamBuffer[i].Lo = StartingBlockIndex + ProcessedBlockCount + i;
      pEncryptor->KeyStreamBuffer[i].Hi = pEncryptor->InitializationVector;
    }

    if (!OD_EncryptKeyStreamBuffer (pEncryptor, KEY_STREAM_BUFFER_BLOCK_COUNT)) {
      return EFI_DEVICE_ERROR;
    }

    for (unsigned i = 0; i != KEY_STREAM_BUFFER_BLOCK_COUNT; i += 1) {
      pOutputBlocks[ProcessedBlockCount].Lo = pInputBlocks[ProcessedBlockCount].Lo ^ pEncryptor->KeyStreamBuffer[i].Lo;
      pOutputBlocks[ProcessedBlockCount].Hi = pInputBlocks[ProcessedBlockCount].Hi ^ pEncryptor->KeyStreamBuffer[i].Hi;
      ProcessedBlockCount                  += 1;
    }
  }

  UINT32  remainingBlocks = DataBlockCount - ProcessedBlockCount;

  if (remainingBlocks > 0) {
    // Encrypt AES blocks in final chunk.

    for (unsigned i = 0; i != remainingBlocks; i += 1) {
      pEncryptor->KeyStreamBuffer[i].Lo = StartingBlockIndex + ProcessedBlockCount + i;
      pEncryptor->KeyStreamBuffer[i].Hi = pEncryptor->InitializationVector;
    }

    if (!OD_EncryptKeyStreamBuffer (pEncryptor, remainingBlocks)) {
      return EFI_DEVICE_ERROR;
    }

    for (unsigned i = 0; i != remainingBlocks; i += 1) {
      pOutputBlocks[ProcessedBlockCount].Lo = pInputBlocks[ProcessedBlockCount].Lo ^ pEncryptor->KeyStreamBuffer[i].Lo;
      pOutputBlocks[ProcessedBlockCount].Hi = pInputBlocks[ProcessedBlockCount].Hi ^ pEncryptor->KeyStreamBuffer[i].Hi;
      ProcessedBlockCount                  += 1;
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
OfflineDumpEncryptorNewKeyInfoBlock (
  IN ENC_DUMP_ALGORITHM       Algorithm,
  IN void const               *pRecipientCertificate,
  IN UINT32                   RecipientCertificateSize,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor,
  OUT ENC_DUMP_KEY_INFO       **ppKeyInfo
  )
{
  EFI_STATUS  Status;

  STACK_OF (X509)* pRecipientStack = NULL;
  BIO                     *pKeyBio       = NULL;
  PKCS7                   *pPkcs7        = NULL;
  OFFLINE_DUMP_ENCRYPTOR  *pNewEncryptor = NULL;
  ENC_DUMP_KEY_INFO       *pNewKeyInfo   = NULL;

  if (Algorithm != ENC_DUMP_ALGORITHM_AES128_CTR) {
    Status = EFI_UNSUPPORTED;
    goto Error;
  }

  pRecipientStack = sk_X509_new_null ();
  if (!pRecipientStack) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  {
    UINT8 const  *pRecipientCertificateBytes = pRecipientCertificate;
    X509         *pRecipient                 = d2i_X509 (NULL, &pRecipientCertificateBytes, RecipientCertificateSize);
    if (!pRecipient) {
      Status = EFI_INVALID_PARAMETER;
      goto Error;
    }

    sk_X509_push (pRecipientStack, pRecipient);
  }

  pKeyBio = BIO_new (BIO_s_mem ());
  if (!pKeyBio) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  Status = OfflineDumpEncryptorNewAes128CtrRandom (&pNewEncryptor);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if (!BIO_write (pKeyBio, pNewEncryptor->Aes128Key, sizeof (pNewEncryptor->Aes128Key))) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  pPkcs7 = PKCS7_encrypt (pRecipientStack, pKeyBio, EVP_aes_128_cbc (), PKCS7_BINARY);
  if (!pPkcs7) {
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  int  Pkcs7Size = i2d_PKCS7 (pPkcs7, NULL);

  if (Pkcs7Size <= 0) {
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  UINT32  KeyInfoSize = sizeof (ENC_DUMP_KEY_INFO) + sizeof (UINT64) + Pkcs7Size;

  KeyInfoSize = (KeyInfoSize + 7u) & ~7u; // Pad to 8-byte boundary.
  pNewKeyInfo = AllocateZeroPool (KeyInfoSize);
  if (!pNewKeyInfo) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  pNewKeyInfo->BlockSize                = KeyInfoSize;
  pNewKeyInfo->Algorithm                = Algorithm;
  pNewKeyInfo->InitializationVectorSize = sizeof (UINT64);
  pNewKeyInfo->EncryptedKeyCmsSize      = (UINT32)Pkcs7Size;

  UINT8  *pKeyInfoData = (UINT8 *)(pNewKeyInfo + 1);

  CopyMem (pKeyInfoData, &pNewEncryptor->InitializationVector, sizeof (UINT64));
  pKeyInfoData += sizeof (UINT64);
  Pkcs7Size     = i2d_PKCS7 (pPkcs7, &pKeyInfoData);
  if (pNewKeyInfo->EncryptedKeyCmsSize != (UINT32)Pkcs7Size) {
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  Status = EFI_SUCCESS;
  goto Done;

Error:

  if (pNewEncryptor) {
    OfflineDumpEncryptorDelete (pNewEncryptor);
    pNewEncryptor = NULL;
  }

  if (pNewKeyInfo) {
    FreePool (pNewKeyInfo);
    pNewKeyInfo = NULL;
  }

Done:

  PKCS7_free (pPkcs7);
  BIO_free (pKeyBio);
  sk_X509_pop_free (pRecipientStack, X509_free);

  *ppEncryptor = pNewEncryptor;
  *ppKeyInfo   = pNewKeyInfo;
  return Status;
}
