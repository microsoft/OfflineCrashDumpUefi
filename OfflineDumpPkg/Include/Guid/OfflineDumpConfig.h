/*
Microsoft Offline Dump - Definitions for communication between firmware and OS.
*/

#ifndef _included_Guid_OfflineDumpConfig_h
#define _included_Guid_OfflineDumpConfig_h

//
// OFFLINE_DUMP_CONFIGURATION_TABLE used to pass information from the firmware to the OS.
//

#define OFFLINE_DUMP_CONFIGURATION_TABLE_GUID  /* 3804CF02-8538-11E2-8847-8DF16088709B */ \
  { 0x3804CF02, 0x8538, 0x11E2, { 0x88, 0x47, 0x8D, 0xF1, 0x60, 0x88, 0x70, 0x9B }}

typedef enum {
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_NONE                 = 0,
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_LOCATION_GPT_SCAN    = 0x01,
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_LOCATION_BYTE_OFFSET = 0x02, // Deprecated
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_RESET_DATA           = 0x04, // Deprecated
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_LOCATION_EFI_SYSTEM  = 0x08, // Deprecated
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_AES_CTR              = 0x10,
} OFFLINE_DUMP_CONFIGURATION_CAPABLE_FLAGS;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_CONFIGURATION_CAPABLE_FLAGS) == 4,
               "OFFLINE_DUMP_CONFIGURATION_CAPABLE_FLAGS should be 4 bytes"
               );

// Deprecated - use OFFLINE_DUMP_CONFIGURATION_TABLE_V3.
typedef struct {
  UINT32                                      Version;
  UINT32                                      AbnormalResetOccurred;
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_FLAGS    OfflineMemoryDumpCapable;
  UINT32                                      Padding1;
  UINT64                                      ResetDataAddress;
  UINT32                                      ResetDataSize;
  UINT32                                      Padding2;
} OFFLINE_DUMP_CONFIGURATION_TABLE_V2;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_CONFIGURATION_TABLE_V2) == 32,
               "OFFLINE_DUMP_CONFIGURATION_TABLE_V2 should be 32 bytes"
               );

typedef struct {
  // Set to 3.
  UINT32                                      Version;

  // 0: No abnormal reset occurred on the most recent system boot.
  // 1: An abnormal reset occurred on the most recent system boot.
  UINT32                                      AbnormalResetOccurred;

  // Capability flags:
  // GPT_SCAN: The firmware supports scanning GPT for a dedicated dump partition.
  // AES128_CTR: The firmware supports encrypting the dump with AES128_CTR + RSAES_OAEP.
  OFFLINE_DUMP_CONFIGURATION_CAPABLE_FLAGS    OfflineMemoryDumpCapable;

  // 0: Offline crash dump generation is disabled or not correctly configured.
  // 1: The device is correctly configured for offline crash dump generation.
  UINT32                                      OfflineMemoryDumpEnabled;

  // 0: The most recent boot did not generate an offline crash dump.
  // 1: The most recent boot generated an offline crash dump due to an abnormal reset.
  UINT32                                      OfflineMemoryDumpExpected;

  // Firmware-defined value indicating reason(s) that the firmware failed to generate an
  // offline crash dump after an abnormal reset.
  UINT32                                      OfflineDumpCreationErrors;
} OFFLINE_DUMP_CONFIGURATION_TABLE_V3;

STATIC_ASSERT (
               sizeof (OFFLINE_DUMP_CONFIGURATION_TABLE_V3) == 24,
               "OFFLINE_DUMP_CONFIGURATION_TABLE_V3 should be 24 bytes"
               );

#define OFFLINE_DUMP_CONFIGURATION_TABLE_CURRENT_VERSION  3
typedef OFFLINE_DUMP_CONFIGURATION_TABLE_V3 OFFLINE_DUMP_CONFIGURATION_TABLE;

//
// Firmware variables used to pass information from the OS to the firmware.
//

// Vendor GUID for firmware variables set by the OS.
#define OFFLINE_DUMP_VARIABLE_GUID  /* 77fa9abd-0359-4d32-bd60-28f4e78f784b */ \
  { 0x77fa9abd, 0x0359, 0x4d32, { 0xBD, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b }}

// OfflineMemoryDumpUseCapability: UINT8 (OFFLINE_DUMP_USE_CAPABILITY_FLAGS).
// Bit 0: Firmware must scan the GPT partition table for the dump partition and
//        write the dump to that partition.
// Bit 1: Deprecated, ignore.
// Bit 2: Deprecated, ignore.
// Bit 3: Deprecated, ignore.
#define OFFLINE_DUMP_USE_CAPABILITY_VARIABLE_NAME  L"OfflineMemoryDumpUseCapability"

// Flags used by the OfflineMemoryDumpUseCapability variable.
typedef enum {
  OFFLINE_DUMP_USE_CAPABILITY_NONE                 = 0,
  OFFLINE_DUMP_USE_CAPABILITY_LOCATION_GPT_SCAN    = 0x01,
  OFFLINE_DUMP_USE_CAPABILITY_LOCATION_BYTE_OFFSET = 0x02,  // Deprecated
  OFFLINE_DUMP_USE_CAPABILITY_RESET_DATA           = 0x04,  // Deprecated
  OFFLINE_DUMP_USE_CAPABILITY_LOCATION_EFI_SYSTEM  = 0x08,  // Deprecated
} OFFLINE_DUMP_USE_CAPABILITY_FLAGS;

// OfflineMemoryDumpOsData: UINT64.
// Windows will persist a book-keeping value in this variable. The firmware should query this
// data and copy it to RAW_DUMP_HEADER.OsData (reference this section) when writing a dump.
#define OFFLINE_DUMP_OS_DATA_VARIABLE_NAME  L"OfflineMemoryDumpOsData"

// OfflineMemoryDumpEncryptionAlgorithm: UINT32 (ENC_DUMP_ALGORITHM).
// ENC_DUMP_ALGORITHM_NONE (0): The firmware may write an unencrypted dump.
// ENC_DUMP_ALGORITHM_AES128_CTR (1): The firmware must encrypt the dump with AES128_CTR.
// Other: Reserved - the firmware must not write a dump.
#define OFFLINE_DUMP_ENCRYPTION_ALGORITHM_VARIABLE_NAME  L"OfflineMemoryDumpEncryptionAlgorithm"

// OfflineMemoryDumpEncryptionPublicKey: Binary.
// X.509 DER-encoded certificate with the public key to be used for key transport when writing
// an encrypted dump.
#define OFFLINE_DUMP_ENCRYPTION_PUBLIC_KEY_VARIABLE_NAME  L"OfflineMemoryDumpEncryptionPublicKey"

//
// GPT partition information
//

// Partition type GUID for the offline dump partition.
// This value is found in EFI_PARTITION_ENTRY::PartitionTypeGUID.
#define OFFLINE_DUMP_PARTITION_TYPE_GUID  /* 66C9B323-F7FC-48B6-BF96-6F32E335A428 */ \
  { 0x66C9B323, 0xF7FC, 0x48B6, { 0xBF, 0x96, 0x6F, 0x32, 0xE3, 0x35, 0xA4, 0x28 }}

//
// GUIDs defined in this header:
//

extern EFI_GUID  gOfflineDumpConfigurationTableGuid;
extern EFI_GUID  gOfflineDumpVariableGuid;
extern EFI_GUID  gOfflineDumpPartitionTypeGuid;

#endif // _included_Guid_OfflineDumpConfig_h
