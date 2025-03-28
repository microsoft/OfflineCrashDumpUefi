// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

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
#include <openssl/aes.h>                    // CryptoPkg/Library/OpensslLib/openssl/include/...
#include <openssl/evp.h>                    // CryptoPkg/Library/OpensslLib/openssl/include/...
#include <openssl/x509.h>                   // CryptoPkg/Library/OpensslLib/openssl/include/...
#include <openssl/pkcs7.h>                  // CryptoPkg/Library/OpensslLib/openssl/include/...

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Library/BaseCryptLib.h>

#if defined (MDE_CPU_X64)
  #include <Register/Intel/Cpuid.h>
#endif // defined (MDE_CPU_X64)

#if defined (MDE_CPU_X64) || defined (MDE_CPU_AARCH64)
#define AES_ACCELERATION_AVAILABLE  1
#else
#define AES_ACCELERATION_AVAILABLE  0
#endif

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

- AesEcbEncrypt (for the fallback implementation).
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

// Function type for aes_set_encrypt_key implementations.
typedef int (EFIAPI AES_SET_ENCRYPT_KEY) (
  const unsigned char  *userKey,
  int                  bits,
  AES_KEY              *key
  );

// Function type for aes_ecb_encrypt implementations.
// Requires: size % 16 == 0.
typedef void (EFIAPI AES_ECB_ENCRYPT) (
  const unsigned char  *in,
  unsigned char        *out,
  size_t               size,
  const AES_KEY        *key
  );

typedef struct {
  AES_SET_ENCRYPT_KEY    *pSetEncryptKey;
  AES_ECB_ENCRYPT        *pEcbEncrypt;
} AES_ENCRYPTION_OPERATIONS;

struct OFFLINE_DUMP_ENCRYPTOR {
  AES_ECB_ENCRYPT       *pEcbEncrypt;
  UINT64                InitializationVector;
  ENC_DUMP_ALGORITHM    Algorithm;
  AES_KEY               Key;
  AES_BLOCK             KeyStreamBuffer[KEY_STREAM_BUFFER_BLOCK_COUNT];
};

typedef struct ALGORITHM_INFO {
  ENC_DUMP_ALGORITHM                 Algorithm;
  UINT8                              KeySize;
  AES_ENCRYPTION_OPERATIONS const    *pOperations;
} ALGORITHM_INFO;

// Used if accelerated implementation is not available.
static int EFIAPI
OD_fallback_aes_set_encrypt_key (
  const unsigned char  *userKey,
  const int            bits,
  AES_KEY              *key
  )
{
  // From openssl/aes.h
  return AES_set_encrypt_key (userKey, bits, key);
}

// Used if accelerated implementation is not available.
// Requires: size % 16 == 0.
static void EFIAPI
OD_fallback_aes_ecb_encrypt (
  const unsigned char  *in,
  unsigned char        *out,
  size_t               size,
  const AES_KEY        *key
  )
{
  ASSERT (size % AES_BLOCK_SIZE == 0);
  for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
    // From openssl/aes.h
    AES_encrypt (in + i, out + i, key);
  }
}

static AES_ENCRYPTION_OPERATIONS const  gFallbackAesEncryptionOperations = {
  .pSetEncryptKey = OD_fallback_aes_set_encrypt_key,
  .pEcbEncrypt    = OD_fallback_aes_ecb_encrypt,
};

#if AES_ACCELERATION_AVAILABLE

// Assembly-language implementations.
AES_SET_ENCRYPT_KEY  OD_accelerated_aes_set_encrypt_key;
AES_ECB_ENCRYPT      OD_accelerated_aes_ecb_encrypt;

static AES_ENCRYPTION_OPERATIONS const  gAcceleratedAesEncryptionOperations = {
  .pSetEncryptKey = OD_accelerated_aes_set_encrypt_key,
  .pEcbEncrypt    = OD_accelerated_aes_ecb_encrypt,
};

#endif // AES_ACCELERATION_AVAILABLE

static ALGORITHM_INFO
OD_GetAlgorithmInfo (
  IN ENC_DUMP_ALGORITHM  Algorithm
  )
{
  ALGORITHM_INFO  Info;

  Info.Algorithm = Algorithm;

  switch (Algorithm) {
    default:
      Info.KeySize     = 0;
      Info.pOperations = NULL;
      goto Done;

    case ENC_DUMP_ALGORITHM_AES128_CTR:
      Info.KeySize = 16;
      break;

    case ENC_DUMP_ALGORITHM_AES192_CTR:
      Info.KeySize = 24;
      break;

    case ENC_DUMP_ALGORITHM_AES256_CTR:
      Info.KeySize = 32;
      break;
  }

 #if AES_ACCELERATION_AVAILABLE

  static BOOLEAN  CheckedAcceleratedAes = FALSE;
  static BOOLEAN  UseAcceleratedAes;

  if (!CheckedAcceleratedAes) {
 #if defined (MDE_CPU_X64)

    CPUID_VERSION_INFO_ECX  Ecx = { 0 };
    AsmCpuid (CPUID_VERSION_INFO, NULL, NULL, &Ecx.Uint32, NULL);
    UseAcceleratedAes = 0 != Ecx.Bits.AESNI;

 #elif defined (MDE_CPU_AARCH64)

    UINT64 const  Isar0 = ArmReadIdAA64Isar0Reg ();
    UseAcceleratedAes = 0 != (ARM_ID_AA64ISAR0_EL1_AES_MASK & (Isar0 >> ARM_ID_AA64ISAR0_EL1_AES_SHIFT));

 #else

    #error "OD_UseAcceleratedAes() not implemented for this architecture"

 #endif

    CheckedAcceleratedAes = TRUE;
  }

  if (UseAcceleratedAes) {
    Info.pOperations = &gAcceleratedAesEncryptionOperations;
    goto Done;
  }

 #endif // !AES_ACCELERATION_AVAILABLE

  Info.pOperations = &gFallbackAesEncryptionOperations;

Done:

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
  ASSERT (AlgorithmInfo.pOperations != NULL);
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

  DEBUG_PRINT (
               DEBUG_INFO,
               "Encryptor: Algorithm %u, KeySize %u, Accelerated %u\n",
               AlgorithmInfo.Algorithm,
               AlgorithmInfo.KeySize,
               AlgorithmInfo.pOperations != &gFallbackAesEncryptionOperations
               );

  pEncryptor->pEcbEncrypt          = AlgorithmInfo.pOperations->pEcbEncrypt;
  pEncryptor->InitializationVector = CtrRandom.InitializationVector;
  pEncryptor->Algorithm            = AlgorithmInfo.Algorithm;

  if (AlgorithmInfo.pOperations->pSetEncryptKey (CtrRandom.Key, AlgorithmInfo.KeySize * 8, &pEncryptor->Key)) {
    DEBUG_PRINT (DEBUG_ERROR, "set_encrypt_key() failed\n");
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
    ZeroMem (pEncryptor, OFFSET_OF (OFFLINE_DUMP_ENCRYPTOR, KeyStreamBuffer));
    FreePool (pEncryptor);
  }
}

static void
OD_EncryptKeyStreamBuffer (
  IN OFFLINE_DUMP_ENCRYPTOR  *pEncryptor,
  IN UINT32                  BlockCount
  )
{
  pEncryptor->pEcbEncrypt (
                           (UINT8 *)pEncryptor->KeyStreamBuffer,
                           (UINT8 *)pEncryptor->KeyStreamBuffer,
                           BlockCount * sizeof (AES_BLOCK),
                           &pEncryptor->Key
                           );
}

void
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

    OD_EncryptKeyStreamBuffer (pEncryptor, KEY_STREAM_BUFFER_BLOCK_COUNT);

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

    OD_EncryptKeyStreamBuffer (pEncryptor, remainingBlocks);

    for (unsigned i = 0; i != remainingBlocks; i += 1) {
      pOutputBlocks[ProcessedBlockCount + i].Lo = pInputBlocks[ProcessedBlockCount + i].Lo ^ pEncryptor->KeyStreamBuffer[i].Lo;
      pOutputBlocks[ProcessedBlockCount + i].Hi = pInputBlocks[ProcessedBlockCount + i].Hi ^ pEncryptor->KeyStreamBuffer[i].Hi;
    }

    ProcessedBlockCount += remainingBlocks;
  }

  return;
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

  if (AlgorithmInfo.pOperations == NULL) {
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
