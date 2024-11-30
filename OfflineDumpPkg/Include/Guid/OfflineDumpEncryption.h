/*
Microsoft Offline Dump - Definitions for dump encryption.
*/

#ifndef _included_Guid_OfflineDumpEncryption_h
#define _included_Guid_OfflineDumpEncryption_h

#include <Uefi/UefiBaseType.h>

// Signature for the encrypted dump header.
// 8 Bytes - "Enc_Dmp!" - in hex, LittleEndian order
#define ENC_DUMP_HEADER_SIGNATURE  (UINT64)(0x21706D445F636E45)

// Algorithms used for dump data encryption.
typedef enum {
  // No encryption.
  ENC_DUMP_ALGORITHM_NONE = 0,

  // AES128_CTR mode encryption.
  // - EncryptedKeyCms content must decrypt to the 16-byte DumpKey (AES128 key).
  // - InitializationVectorSize is an 8-byte random value.
  // - ENC_DUMP_CTR_COUNTER (little-endian) is the structure for the counter.
  //
  // Both encryption and decryption are performed using 16-byte blocks as follows:
  // OutputBlock[N] = InputBlock[N] XOR AesEncryptBlock<DumpKey>(ENC_DUMP_CTR_COUNTER{N, IV})
  //
  // If input is not a multiple of 16 bytes, the last block is padded to a multiple of 16 bytes,
  // the encryption/decryption is performed, and then the output is truncated to the original
  // size.
  ENC_DUMP_ALGORITHM_AES128_CTR = 1,

  // AES192_CTR mode encryption: Same as AES128_CTR, but with 24-byte DumpKey (AES192 key).
  ENC_DUMP_ALGORITHM_AES192_CTR = 2,

  // AES256_CTR mode encryption: Same as AES128_CTR, but with 32-byte DumpKey (AES256 key).
  ENC_DUMP_ALGORITHM_AES256_CTR = 3,
} ENC_DUMP_ALGORITHM;

STATIC_ASSERT (
               sizeof (ENC_DUMP_ALGORITHM) == 4,
               "ENC_DUMP_ALGORITHM should be 4 bytes"
               );

// Encrypted dump header.
// Encrypted dump = ENC_DUMP_HEADER + ENC_DUMP_KEY_INFO block + Encrypt(Unencrypted dump).
typedef struct {
  UINT64    Signature;     // ENC_DUMP_HEADER_SIGNATURE
  UINT32    HeaderSize;    // sizeof(ENC_DUMP_HEADER)
  UINT32    KeyInfoOffset; // offset from start of ENC_DUMP_HEADER to start of ENC_DUMP_KEY_INFO.
  UINT32    RawDumpOffset; // offset from start of ENC_DUMP_HEADER to start of encrypted RAW_DUMP_HEADER.
  UINT32    Reserved;      // Reserved for future use (padding for 8-byte structure size).
  // Followed by ENC_DUMP_KEY_INFO block.
  // Followed by Encrypt(Unencrypted dump).
} ENC_DUMP_HEADER;

STATIC_ASSERT (
               sizeof (ENC_DUMP_HEADER) == 24,
               "ENC_DUMP_HEADER should be 24 bytes"
               );

// Encrypted dump key information.
// ENC_DUMP_KEY_INFO block = ENC_DUMP_KEY_INFO + InitializationVector + EncryptedKeyCms + padding.
typedef struct {
  UINT32                BlockSize;                // sizeof(ENC_DUMP_KEY_INFO + InitializationVector + EncryptedKeyCms + padding).
  ENC_DUMP_ALGORITHM    Algorithm;                // Encryption algorithm used, e.g. ENC_DUMP_ALGORITHM_AES???_CTR.
  UINT32                InitializationVectorSize; // Size of InitializationVector in bytes, e.g. 8 for AES???_CTR.
  UINT32                EncryptedKeyCmsSize;      // Size of EncryptedKeyCms in bytes.
  // Followed by InitializationVectorSize bytes of InitializationVector data.
  // Followed by EncryptedKeyCmsSize bytes of EncryptedKeyCms data.
  // Followed by 0..7 bytes of padding as needed to make BlockSize a multiple of 8.
} ENC_DUMP_KEY_INFO;

STATIC_ASSERT (
               sizeof (ENC_DUMP_KEY_INFO) == 16,
               "ENC_DUMP_KEY_INFO should be 16 bytes"
               );

// Counter value for AES???_CTR mode encryption.
// CounterLow is set to 0 for the first 16-byte block, 1 for the next block, etc.
// CounterHigh is set to the 8-byte InitializationVector.
typedef struct {
  UINT64    CounterLow;  // Set to RawDumpBlockIndex, i.e. RawDumpBytePos / 16.
  UINT64    CounterHigh; // Set to IV.
} ENC_DUMP_CTR_COUNTER;

STATIC_ASSERT (
               sizeof (ENC_DUMP_CTR_COUNTER) == 16,
               "ENC_DUMP_CTR_COUNTER should be 16 bytes"
               );

#endif // _included_Guid_OfflineDumpEncryption_h
