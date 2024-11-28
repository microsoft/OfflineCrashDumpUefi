/*
Microsoft Offline Dump - Functions for encrypting data for an Offline Dump.

Consumes:
  MemoryAllocationLib
  BaseCryptLib
  OpensslLib
*/

#ifndef _included_Library_OfflineDumpEncryptor_h
#define _included_Library_OfflineDumpEncryptor_h

#include <Uefi/UefiBaseType.h>
#include <Guid/OfflineDumpEncryption.h>

// Forward decaration of the opaque OFFLINE_DUMP_ENCRYPTOR object.
typedef struct OFFLINE_DUMP_ENCRYPTOR OFFLINE_DUMP_ENCRYPTOR;

// Destroys and frees an Encryptor object.
void
OfflineDumpEncryptorDelete (
  IN OUT OFFLINE_DUMP_ENCRYPTOR  *pEncryptor
  );

// Creates an OFFLINE_DUMP_ENCRYPTOR and a ENC_DUMP_KEY_INFO block for the specified
// algorithm and recipient. Algorithm will typically come from the
// OfflineMemoryDumpEncryptionAlgorithm variable. pRecipientCertificate will typically
// come from the OfflineMemoryDumpEncryptionPublicKey variable.
//
// This function will do the following:
//
// 1. Validate the Algorithm and RecipientCertificate.
// 2. Create a random AES key and IV.
// 3. Create an Encryptor with the key and IV.
// 4. Create a ENC_DUMP_KEY_INFO block with the algorithm, IV, and an encrypted key that
//    can be decrypted with the private key specified in the certificate.
// 5. Return the Encryptor and KeyInfo block. The caller must free these via
//    EncryptorAes128CtrDestroy(*ppEncryptor) and FreePool(*ppKeyInfoBlock).
EFI_STATUS
OfflineDumpEncryptorNewKeyInfoBlock (
  IN ENC_DUMP_ALGORITHM       Algorithm,
  IN void const               *pRecipientCertificate,
  IN UINT32                   RecipientCertificateSize,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor,
  OUT ENC_DUMP_KEY_INFO       **ppKeyInfoBlock
  );

// Converts DataSize bytes of plaintext InputData into encrypted OutputData.
//
// StartingByteOffset is the offset of the first byte of InputData relative to the first
// byte of RAW_DUMP_HEADER.  It is NOT an offset into pInputData or  pOutputData. It is
// used as input to the encryption process (incorrect offset will result in garbage
// output).
//
// This operation is most efficient when StartingByteOffset and DataSize are multiples of
// 16 and pInputData and pOutputData are 8-byte aligned. (TODO: Reject unaligned input?)
//
// In-place operation is supported, i.e. pInputData and pOutputData may point to the same
// place.
EFI_STATUS
OfflineDumpEncryptorEncrypt (
  IN OFFLINE_DUMP_ENCRYPTOR  *pEncryptor,
  IN UINT64                  StartingByteOffset,
  IN UINT32                  DataSize,
  IN void const              *pInputData,
  OUT void                   *pOutputData
  );

// Creates a new OFFLINE_DUMP_ENCRYPTOR object for AES128-CTR with the specified Key and IV.
//
// This function exists primarily for testing purposes. In normal usage, you'll use
// EncryptorNewKeyInfoBlock instead of creating an Encryptor directly.
EFI_STATUS
OfflineDumpEncryptorNewAes128Ctr (
  IN UINT8 const              Key[16],
  IN UINT64                   IV,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor
  );

// Creates a new OFFLINE_DUMP_ENCRYPTOR object for AES128-CTR with random key and IV.
//
// This function exists primarily for testing purposes. In normal usage, you'll use
// EncryptorNewKeyInfoBlock instead of creating an Encryptor directly.
EFI_STATUS
OfflineDumpEncryptorNewAes128CtrRandom (
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor
  );

#endif // _included_Library_OfflineDumpEncryptor_h
