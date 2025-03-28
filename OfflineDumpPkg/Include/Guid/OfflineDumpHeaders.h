// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
Microsoft Offline Dump - Definitions for dump file format.
*/

#ifndef _included_Guid_OfflineDumpHeaders_h
#define _included_Guid_OfflineDumpHeaders_h

#pragma pack(push,1)

// Signature for the raw dump file header.
// 8 Bytes - "Raw_Dmp!" - in hex, LittleEndian order
#define RAW_DUMP_HEADER_SIGNATURE  (UINT64)(0x21706D445F776152)

#define RAW_DUMP_HEADER_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_HEADER_CURRENT_MINOR_VERSION  0

// Flags for RAW_DUMP_HEADER.
typedef enum {
  RAW_DUMP_HEADER_NONE                     = 0,
  RAW_DUMP_HEADER_DUMP_VALID               = 0x01, // This dump was successfully written.
  RAW_DUMP_HEADER_INSUFFICIENT_STORAGE     = 0x02, // The dump is incomplete due to insufficient storage.
  RAW_DUMP_HEADER_IS_HYPERV_DATA_PROTECTED = 0x04, // All Hyper-V/SecureKernel memory is redacted or encrypted.
  RAW_DUMP_HEADER_IS_DDR_CACHE_FLUSHED     = 0x08, // DDR cache was successfully flushed before the warm reset.
} RAW_DUMP_HEADER_FLAGS;

STATIC_ASSERT (
               sizeof (RAW_DUMP_HEADER_FLAGS) == 4,
               "RAW_DUMP_HEADER_FLAGS should be 4 bytes"
               );

// Raw dump header.
// The raw dump is: RAW_DUMP_HEADER + RAW_DUMP_SECTION_HEADER[SectionsCount] + section data.
typedef struct {
  UINT64                   Signature;    // Set to RAW_DUMP_HEADER_SIGNATURE.
  UINT16                   MajorVersion; // Set to 1. Back-compat: if MajorVersion > 4096, treat as v0.MajorVersion, e.g. 0.4096
  UINT16                   MinorVersion; // Set to 0.
  RAW_DUMP_HEADER_FLAGS    Flags;
  UINT64                   OsData;
  UINT64                   CpuContext;            // Deprecated, set to 0.
  UINT32                   ResetTrigger;          // Deprecated, set to 0.
  UINT64                   DumpSize;              // Size of the written dump data from start of RAW_DUMP_HEADER to end of last section's data.
  UINT64                   TotalDumpSizeRequired; // If dump fails due to insufficient storage, set to the storage size required.
  UINT32                   SectionsCount;         // Number of RAW_DUMP_SECTION_HEADER structures following this header.
  // Immediately followed (no padding) by: RAW_DUMP_SECTION_HEADER Sections[SectionsCount];
} RAW_DUMP_HEADER;

STATIC_ASSERT (
               sizeof (RAW_DUMP_HEADER) == 56,
               "RAW_DUMP_HEADER should be 56 bytes"
               );

// Architecture for RAW_DUMP_SECTION_INFORMATION_SYSTEM_INFORMATION.
typedef enum {
  RAW_DUMP_ARCHITECTURE_ARM64 = 0,
  RAW_DUMP_ARCHITECTURE_X64   = 1,
} RAW_DUMP_ARCHITECTURE;

STATIC_ASSERT (
               sizeof (RAW_DUMP_ARCHITECTURE) == 4,
               "RAW_DUMP_ARCHITECTURE should be 4 bytes"
               );

// Flags for RAW_DUMP_SECTION_HEADER.
typedef enum {
  RAW_DUMP_SECTION_HEADER_NONE                 = 0,
  RAW_DUMP_SECTION_HEADER_DUMP_VALID           = 0x01,  // This section was successfully written.
  RAW_DUMP_SECTION_HEADER_INSUFFICIENT_STORAGE = 0x02,  // This section was not written due to insufficient storage.
} RAW_DUMP_SECTION_HEADER_FLAGS;

STATIC_ASSERT (
               sizeof (RAW_DUMP_SECTION_HEADER_FLAGS) == 4,
               "RAW_DUMP_SECTION_HEADER_FLAGS should be 4 bytes"
               );

// Type for RAW_DUMP_SECTION_HEADER.
typedef enum {
  RAW_DUMP_SECTION_NONE               = 0,
  RAW_DUMP_SECTION_DDR_RANGE          = 1,
  RAW_DUMP_SECTION_CPU_CONTEXT        = 2,
  RAW_DUMP_SECTION_SV_SPECIFIC        = 3,
  RAW_DUMP_SECTION_DUMP_REASON        = 4,
  RAW_DUMP_SECTION_SYSTEM_INFORMATION = 5,
} RAW_DUMP_SECTION_TYPE;

STATIC_ASSERT (
               sizeof (RAW_DUMP_SECTION_TYPE) == 4,
               "RAW_DUMP_SECTION_TYPE should be 4 bytes"
               );

// Information for RAW_DUMP_SECTION_HEADER when Type is DDR_RANGE.
typedef struct {
  UINT64    Base;
} RAW_DUMP_SECTION_INFORMATION_DDR_RANGE;

#define RAW_DUMP_DDR_RANGE_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_DDR_RANGE_CURRENT_MINOR_VERSION  0

// Information for RAW_DUMP_SECTION_HEADER when Type is CPU_CONTEXT.
typedef struct {
  UINT16    Architecture; // PROCESSOR_ARCHITECTURE_* from OfflineDumpCpuContext.h.
  UINT32    CoreCount;
  UINT32    ContextSize; // sizeof(CONTEXT_*) from OfflineDumpCpuContext.h.
} RAW_DUMP_SECTION_INFORMATION_CPU_CONTEXT;

#define RAW_DUMP_CPU_CONTEXT_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_CPU_CONTEXT_CURRENT_MINOR_VERSION  0

// Information for RAW_DUMP_SECTION_HEADER when Type is SV_SPECIFIC.
typedef struct {
  UINT8    SVSpecificData[16];
} RAW_DUMP_SECTION_INFORMATION_SV_SPECIFIC;

#define RAW_DUMP_SV_SPECIFIC_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_SV_SPECIFIC_CURRENT_MINOR_VERSION  0

// Information for RAW_DUMP_SECTION_HEADER when Type is DUMP_REASON.
typedef struct {
  UINT32    Parameter1; // Primary bucketization parameter
  UINT32    Parameter2; // Secondary bucketization parameter
  UINT32    Parameter3; // Reserved
  UINT32    Parameter4; // Reserved
} RAW_DUMP_SECTION_INFORMATION_DUMP_REASON;

#define RAW_DUMP_DUMP_REASON_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_DUMP_REASON_CURRENT_MINOR_VERSION  0

// Information for RAW_DUMP_SECTION_HEADER when Type is SYSTEM_INFORMATION.
typedef struct {
  CHAR8                    Vendor[4];   // 4-character vendor ACPI ID.
  CHAR8                    Platform[8]; // 8-character silicon vendor platform ID.
  RAW_DUMP_ARCHITECTURE    Architecture;
} RAW_DUMP_SECTION_INFORMATION_SYSTEM_INFORMATION;

#define RAW_DUMP_SYSTEM_INFORMATION_CURRENT_MAJOR_VERSION  1
#define RAW_DUMP_SYSTEM_INFORMATION_CURRENT_MINOR_VERSION  0

// Information for RAW_DUMP_SECTION_HEADER. Active field selected by Type.
typedef union {
  RAW_DUMP_SECTION_INFORMATION_DDR_RANGE             DdrRange;
  RAW_DUMP_SECTION_INFORMATION_CPU_CONTEXT           CpuContext;
  RAW_DUMP_SECTION_INFORMATION_SV_SPECIFIC           SVSpecific;
  RAW_DUMP_SECTION_INFORMATION_DUMP_REASON           DumpReason;
  RAW_DUMP_SECTION_INFORMATION_SYSTEM_INFORMATION    SystemInformation;
  UINT8                                              Bytes[16];
} RAW_DUMP_SECTION_INFORMATION;

STATIC_ASSERT (
               sizeof (RAW_DUMP_SECTION_INFORMATION) == 16,
               "RAW_DUMP_SECTION_INFORMATION should be 16 bytes"
               );

// Raw dump section header - array of section headers follows the RAW_DUMP_HEADER.
typedef struct {
  RAW_DUMP_SECTION_HEADER_FLAGS    Flags;
  UINT16                           MajorVersion; // Varies based on section type. If MajorVersion > 4096, treat as v0.MajorVersion, e.g. 0.4096
  UINT16                           MinorVersion; // Varies based on section type.
  RAW_DUMP_SECTION_TYPE            Type;
  UINT64                           Offset;      // Offset from the start of the RAW_DUMP_HEADER to the start of the section data.
  UINT64                           Size;        // Size of the section data.
  RAW_DUMP_SECTION_INFORMATION     Information; // Varies based on Type.
  CHAR8                            Name[20];
} RAW_DUMP_SECTION_HEADER;

STATIC_ASSERT (
               sizeof (RAW_DUMP_SECTION_HEADER) == 64,
               "RAW_DUMP_SECTION_HEADER should be 64 bytes"
               );

#pragma pack(pop)
#endif // _included_Guid_OfflineDumpHeaders_h
