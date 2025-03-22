/*
Microsoft Offline Dump - Functions for encrypting data for an Offline Dump.

Consumes:
  MemoryAllocationLib
  BaseCryptLib
  OpensslLib
*/

#ifndef _included_OfflineDumpEncryptor_h
#define _included_OfflineDumpEncryptor_h

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
//    OfflineDumpEncryptorDelete(*ppEncryptor) and FreePool(*ppKeyInfoBlock).
EFI_STATUS
OfflineDumpEncryptorNewKeyInfoBlock (
  IN ENC_DUMP_ALGORITHM       Algorithm,
  IN void const               *pRecipientCertificate,
  IN UINT32                   RecipientCertificateSize,
  OUT OFFLINE_DUMP_ENCRYPTOR  **ppEncryptor,
  OUT ENC_DUMP_KEY_INFO       **ppKeyInfoBlock
  );

// Converts DataSize bytes of plaintext InputData into encrypted OutputData.
// DataSize and StartingByteOffset must be multiples of 16.
//
// StartingByteOffset is NOT an offset into pInputData or  pOutputData. It is the output
// offset (in bytes) of pInputData[0] relative to the start of the encrypted data. This
// value is used as input to the encryption process (incorrect offset will result in
// garbage output). For example, if encrypting the dump and pInputData points at the
// RAW_DUMP_HEADER, the StartingByteOffset should be 0, and if encrypting dump section
// data for a section starting at offset N, the StartingByteOffset should be N.
//
// In-place operation is supported, i.e. pInputData and pOutputData may point to the same
// place. Other kinds of overlap between the buffers may have unpredictable results.
void
OfflineDumpEncryptorEncrypt (
  IN OFFLINE_DUMP_ENCRYPTOR  *pEncryptor,
  IN UINT64                  StartingByteOffset,
  IN UINT32                  DataSize,
  IN void const              *pInputData,
  OUT void                   *pOutputData
  );

// Returns the ENC_DUMP_ALGORITHM used by the Encryptor.
ENC_DUMP_ALGORITHM
OfflineDumpEncryptorAlgorithm (
  IN OFFLINE_DUMP_ENCRYPTOR const  *pEncryptor OPTIONAL
  );

#endif // _included_OfflineDumpEncryptor_h
