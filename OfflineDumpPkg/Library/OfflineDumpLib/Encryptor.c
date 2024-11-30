#include <OfflineDumpEncryptor.h>

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

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Library/BaseCryptLib.h>

#define DEBUG_PRINT(bits, fmt, ...)  _DEBUG_PRINT(bits, "%a: " fmt, __func__, ##__VA_ARGS__)

/*
TODO: Don't depend on private headers from OpenSslLib.

Almost-useful functions from BaseCryptLib.h:

- AesInit
- AesCbcEncrypt
- RsaGetPublicKeyFromX509, RsaFree
- X509ConstructCertificate, X509Free
- X509Get***
- RsaOaepEncrypt
- RandomBytes

To be able to use BaseCryptLib.h instead of <openssl/???.h>, we would need:

- AesEcbEncrypt (AES-NI optimizations are REQUIRED).
- Pkcs7Encrypt - could be implemented using RsaOaepEncrypt + an ASN.1 writer from somewhere.
*/

enum {
  KEY_STREAM_BUFFER_SIZE        = 8 * SIZE_1KB,
  KEY_STREAM_BUFFER_BLOCK_COUNT = KEY_STREAM_BUFFER_SIZE / sizeof (AES_BLOCK),
  AES_BLOCK_MASK                = AES_BLOCK_SIZE - 1,
};

STATIC_ASSERT (
               KEY_STREAM_BUFFER_SIZE == KEY_STREAM_BUFFER_BLOCK_COUNT * sizeof (AES_BLOCK),
               "KeyStreamBufferSize must be a multiple of 16"
               );

struct OFFLINE_DUMP_ENCRYPTOR {
  EVP_CIPHER_CTX        *pCipherCtx;
  UINT64                InitializationVector;
  ENC_DUMP_ALGORITHM    Algorithm;
  AES_BLOCK             KeyStreamBuffer[KEY_STREAM_BUFFER_BLOCK_COUNT];
};

typedef struct ALGORITHM_INFO {
  ENC_DUMP_ALGORITHM    Algorithm;
  UINT8                 KeySize;
  EVP_CIPHER const      *pCipher;
} ALGORITHM_INFO;

static ALGORITHM_INFO
OD_GetAlgorithmInfo (
  IN ENC_DUMP_ALGORITHM  Algorithm
  )
{
  ALGORITHM_INFO  Info = { Algorithm, 0, NULL };

  switch (Algorithm) {
    default:
      Info.KeySize = 0;
      Info.pCipher = NULL;
      break;
    case ENC_DUMP_ALGORITHM_AES128_CTR:
      Info.KeySize = 16;
      Info.pCipher = EVP_aes_128_ecb ();
      break;
    case ENC_DUMP_ALGORITHM_AES192_CTR:
      Info.KeySize = 24;
      Info.pCipher = EVP_aes_192_ecb ();
      break;
    case ENC_DUMP_ALGORITHM_AES256_CTR:
      Info.KeySize = 32;
      Info.pCipher = EVP_aes_256_ecb ();
      break;
  }

  return Info;
}

// Creates a new encryptor for the specified algorithm.
// Writes key to pKeyBio.
static EFI_STATUS
OD_EncryptorNew (
  IN ALGORITHM_INFO           AlgorithmInfo,
  IN OUT BIO                  *pKeyBio,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor
  )
{
  ASSERT (AlgorithmInfo.pCipher != NULL);
  ASSERT (pKeyBio != NULL);
  ASSERT (ppEncryptor != NULL);

  EFI_STATUS              Status;
  OFFLINE_DUMP_ENCRYPTOR  *pEncryptor = NULL;

  struct ENCRYPTOR_KEY_INFO {
    UINT64    InitializationVector;
    UINT8     Key[32];
  } CtrRandom;

  ASSERT (AlgorithmInfo.KeySize <= sizeof (CtrRandom.Key));
  if (AlgorithmInfo.KeySize > sizeof (CtrRandom.Key)) {
    DEBUG_PRINT (
                 DEBUG_ERROR,
                 "KeySize %u too large, max supported is %u\n",
                 AlgorithmInfo.KeySize,
                 (unsigned)sizeof (CtrRandom.Key)
                 );
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (!RandomBytes ((UINT8 *)&CtrRandom, sizeof (CtrRandom))) {
    DEBUG_PRINT (DEBUG_ERROR, "RandomBytes() failed\n");
    Status = EFI_NOT_READY;
    goto Done;
  }

  pEncryptor = AllocatePool (sizeof (*pEncryptor));
  if (pEncryptor == NULL) {
    DEBUG_PRINT (DEBUG_ERROR, "AllocatePool(OFFLINE_DUMP_ENCRYPTOR) failed\n");
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  EVP_CIPHER_CTX *const  pCipherCtx = EVP_CIPHER_CTX_new ();

  if (pCipherCtx == NULL) {
    DEBUG_PRINT (DEBUG_ERROR, "EVP_CIPHER_CTX_new() failed\n");
    FreePool (pEncryptor);
    pEncryptor = NULL;
    Status     = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  pEncryptor->pCipherCtx           = pCipherCtx;
  pEncryptor->InitializationVector = CtrRandom.InitializationVector;
  pEncryptor->Algorithm            = AlgorithmInfo.Algorithm;

  if (!EVP_EncryptInit (pCipherCtx, AlgorithmInfo.pCipher, CtrRandom.Key, NULL)) {
    DEBUG_PRINT (DEBUG_ERROR, "EVP_EncryptInit() failed\n");
  } else if (!EVP_CIPHER_CTX_set_padding (pCipherCtx, 0)) {
    DEBUG_PRINT (DEBUG_ERROR, "EVP_CIPHER_CTX_set_padding() failed\n");
  } else if (!BIO_write (pKeyBio, CtrRandom.Key, AlgorithmInfo.KeySize)) {
    DEBUG_PRINT (DEBUG_ERROR, "BIO_write() failed\n");
  } else {
    Status = EFI_SUCCESS;
    goto Done;
  }

  OfflineDumpEncryptorDelete (pEncryptor);
  pEncryptor = NULL;
  Status     = EFI_DEVICE_ERROR;

Done:

  ASSERT (EFI_ERROR (Status) == (pEncryptor == NULL));
  ZeroMem (&CtrRandom, sizeof (CtrRandom));

  *ppEncryptor = pEncryptor;
  return Status;
}

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
  if (!Ok) {
    DEBUG_PRINT (DEBUG_ERROR, "EVP_EncryptUpdate() failed\n");
  }

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
  ASSERT (0 == (StartingByteOffset & AES_BLOCK_MASK));
  ASSERT (0 == (DataSize & AES_BLOCK_MASK));

  UINT64 const      StartingBlockIndex = StartingByteOffset / AES_BLOCK_SIZE;
  AES_BLOCK *const  pInputBlocks       = (AES_BLOCK *)pInputData;
  AES_BLOCK *const  pOutputBlocks      = (AES_BLOCK *)pOutputData;
  UINT32 const      DataBlockCount     = DataSize / AES_BLOCK_SIZE;

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
      pOutputBlocks[ProcessedBlockCount + i].Lo = pInputBlocks[ProcessedBlockCount + i].Lo ^ pEncryptor->KeyStreamBuffer[i].Lo;
      pOutputBlocks[ProcessedBlockCount + i].Hi = pInputBlocks[ProcessedBlockCount + i].Hi ^ pEncryptor->KeyStreamBuffer[i].Hi;
    }

    ProcessedBlockCount += KEY_STREAM_BUFFER_BLOCK_COUNT;
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
      pOutputBlocks[ProcessedBlockCount + i].Lo = pInputBlocks[ProcessedBlockCount + i].Lo ^ pEncryptor->KeyStreamBuffer[i].Lo;
      pOutputBlocks[ProcessedBlockCount + i].Hi = pInputBlocks[ProcessedBlockCount + i].Hi ^ pEncryptor->KeyStreamBuffer[i].Hi;
    }

    ProcessedBlockCount += remainingBlocks;
  }

  return EFI_SUCCESS;
}

ENC_DUMP_ALGORITHM
OfflineDumpEncryptorAlgorithm (
  IN OFFLINE_DUMP_ENCRYPTOR const  *pEncryptor OPTIONAL
  )
{
  return pEncryptor ? pEncryptor->Algorithm : ENC_DUMP_ALGORITHM_NONE;
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
  BIO                     *pKeyBio     = NULL;
  PKCS7                   *pPkcs7      = NULL;
  OFFLINE_DUMP_ENCRYPTOR  *pEncryptor  = NULL;
  ENC_DUMP_KEY_INFO       *pNewKeyInfo = NULL;

  ALGORITHM_INFO  const  AlgorithmInfo = OD_GetAlgorithmInfo (Algorithm);

  if (AlgorithmInfo.pCipher == NULL) {
    DEBUG_PRINT (DEBUG_ERROR, "Unsupported Algorithm %u\n", Algorithm);
    Status = EFI_UNSUPPORTED;
    goto Error;
  }

  pRecipientStack = sk_X509_new_null ();
  if (!pRecipientStack) {
    DEBUG_PRINT (DEBUG_ERROR, "sk_X509_new_null() failed\n");
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  {
    UINT8 const  *pRecipientCertificateBytes = pRecipientCertificate;
    X509         *pRecipient                 = d2i_X509 (NULL, &pRecipientCertificateBytes, RecipientCertificateSize);
    if (!pRecipient) {
      DEBUG_PRINT (DEBUG_ERROR, "d2i_X509() failed\n");
      Status = EFI_INVALID_PARAMETER;
      goto Error;
    }

    sk_X509_push (pRecipientStack, pRecipient);
  }

  pKeyBio = BIO_new (BIO_s_mem ());
  if (!pKeyBio) {
    DEBUG_PRINT (DEBUG_ERROR, "BIO_new(BIO_s_mem()) failed\n");
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  // Randomly generate a key and an initialization vector.
  // Write the key to pKeyBio.
  // Create an Encryptor with the key and IV.
  Status = OD_EncryptorNew (AlgorithmInfo, pKeyBio, &pEncryptor);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  // pKeyBio now contains the dump key. Wrap it in a CMS (PKCS7) envelope.
  // We may be wrapping a 128, 192, or 256-bit key. Key wrapping algorithm must be at
  // least as strong as the key being wrapped, so wrap using AES-256-CBC.
  pPkcs7 = PKCS7_encrypt (pRecipientStack, pKeyBio, EVP_aes_256_cbc (), PKCS7_BINARY);
  if (!pPkcs7) {
    DEBUG_PRINT (DEBUG_ERROR, "PKCS7_encrypt() failed\n");
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  int  Pkcs7Size = i2d_PKCS7 (pPkcs7, NULL);

  if (Pkcs7Size <= 0) {
    DEBUG_PRINT (DEBUG_ERROR, "i2d_PKCS7() failed\n");
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  UINT32  KeyInfoSize = sizeof (ENC_DUMP_KEY_INFO) + sizeof (UINT64) + Pkcs7Size;

  KeyInfoSize = (KeyInfoSize + 7u) & ~7u; // Pad to 8-byte boundary.
  pNewKeyInfo = AllocateZeroPool (KeyInfoSize);
  if (!pNewKeyInfo) {
    DEBUG_PRINT (DEBUG_ERROR, "AllocateZeroPool(KeyInfoSize = %u) failed\n", KeyInfoSize);
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }

  pNewKeyInfo->BlockSize                = KeyInfoSize;
  pNewKeyInfo->Algorithm                = Algorithm;
  pNewKeyInfo->InitializationVectorSize = sizeof (UINT64);
  pNewKeyInfo->EncryptedKeyCmsSize      = (UINT32)Pkcs7Size;

  UINT8  *pKeyInfoData = (UINT8 *)(pNewKeyInfo + 1);

  CopyMem (pKeyInfoData, &pEncryptor->InitializationVector, sizeof (UINT64));
  pKeyInfoData += sizeof (UINT64);
  Pkcs7Size     = i2d_PKCS7 (pPkcs7, &pKeyInfoData);
  if (pNewKeyInfo->EncryptedKeyCmsSize != (UINT32)Pkcs7Size) {
    DEBUG_PRINT (DEBUG_ERROR, "i2d_PKCS7() returned %d, expected %u\n", Pkcs7Size, pNewKeyInfo->EncryptedKeyCmsSize);
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  Status = EFI_SUCCESS;
  goto Done;

Error:

  if (pEncryptor) {
    OfflineDumpEncryptorDelete (pEncryptor);
    pEncryptor = NULL;
  }

  if (pNewKeyInfo) {
    FreePool (pNewKeyInfo);
    pNewKeyInfo = NULL;
  }

Done:

  PKCS7_free (pPkcs7);
  BIO_free (pKeyBio);
  sk_X509_pop_free (pRecipientStack, X509_free);

  *ppEncryptor = pEncryptor;
  *ppKeyInfo   = pNewKeyInfo;
  return Status;
}
