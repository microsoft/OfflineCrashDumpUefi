/*
Microsoft Offline Dump - Definitions for CPU context information.
*/

#ifndef _included_Guid_OfflineDumpCpuContext_h
#define _included_Guid_OfflineDumpCpuContext_h

#include <Uefi/UefiBaseType.h>

#ifdef DUMMYSTRUCTNAME
#define CPU_CONTEXT_DUMMYSTRUCTNAME  DUMMYSTRUCTNAME
#else
#define CPU_CONTEXT_DUMMYSTRUCTNAME  s
#endif

#ifdef DUMMYUNIONNAME
#define CPU_CONTEXT_DUMMYUNIONNAME  DUMMYUNIONNAME
#else
#define CPU_CONTEXT_DUMMYUNIONNAME  u
#endif

//
// PROCESSOR_ARCHITECTURE_AMD64
//

// For use in RAW_DUMP_SECTION_INFORMATION_CPU_CONTEXT field Architecture.
// From winnt.h: PROCESSOR_ARCHITECTURE_AMD64.
#define PROCESSOR_ARCHITECTURE_AMD64  9

// A 128-bit XMM register.
// From winnt.h: M128A.
typedef struct {
  UINT64    Low;
  INT64     High;
} M128A;

STATIC_ASSERT (
               sizeof (M128A) == 16,
               "M128A should be 16 bytes"
               );

// XSAVE_FORMAT: AMD64 floating point state.
// From winnt.h: XSAVE_FORMAT for _M_AMD64.
typedef struct {
  UINT16    ControlWord;
  UINT16    StatusWord;
  UINT8     TagWord;
  UINT8     Reserved1;
  UINT16    ErrorOpcode;
  UINT32    ErrorOffset;
  UINT16    ErrorSelector;
  UINT16    Reserved2;
  UINT32    DataOffset;
  UINT16    DataSelector;
  UINT16    Reserved3;
  UINT32    MxCsr;
  UINT32    MxCsr_Mask;
  M128A     FloatRegisters[8];

  M128A     XmmRegisters[16];
  UINT8     Reserved4[96];
} XSAVE_FORMAT;

STATIC_ASSERT (
               sizeof (XSAVE_FORMAT) == 512,
               "XSAVE_FORMAT should be 512 bytes"
               );

// CONTEXT_AMD64: AMD64 processor context for use in RAW_DUMP_SECTION_CPU_CONTEXT data.
// From winnt.h: CONTEXT for _M_AMD64.
typedef struct {
  //
  // Register parameter home addresses.
  //
  // N.B. These fields are for convience - they could be used to extend the
  //      context record in the future.
  //

  UINT64    P1Home;
  UINT64    P2Home;
  UINT64    P3Home;
  UINT64    P4Home;
  UINT64    P5Home;
  UINT64    P6Home;

  //
  // Control flags.
  //

  UINT32    ContextFlags;
  UINT32    MxCsr;

  //
  // Segment Registers and processor flags.
  //

  UINT16    SegCs;
  UINT16    SegDs;
  UINT16    SegEs;
  UINT16    SegFs;
  UINT16    SegGs;
  UINT16    SegSs;
  UINT32    EFlags;

  //
  // Debug registers
  //

  UINT64    Dr0;
  UINT64    Dr1;
  UINT64    Dr2;
  UINT64    Dr3;
  UINT64    Dr6;
  UINT64    Dr7;

  //
  // Integer registers.
  //

  UINT64    Rax;
  UINT64    Rcx;
  UINT64    Rdx;
  UINT64    Rbx;
  UINT64    Rsp;
  UINT64    Rbp;
  UINT64    Rsi;
  UINT64    Rdi;
  UINT64    R8;
  UINT64    R9;
  UINT64    R10;
  UINT64    R11;
  UINT64    R12;
  UINT64    R13;
  UINT64    R14;
  UINT64    R15;

  //
  // Program counter.
  //

  UINT64    Rip;

  //
  // Floating point state.
  //

  union {
    XSAVE_FORMAT    FltSave;
    struct {
      M128A    Header[2];
      M128A    Legacy[8];
      M128A    Xmm0;
      M128A    Xmm1;
      M128A    Xmm2;
      M128A    Xmm3;
      M128A    Xmm4;
      M128A    Xmm5;
      M128A    Xmm6;
      M128A    Xmm7;
      M128A    Xmm8;
      M128A    Xmm9;
      M128A    Xmm10;
      M128A    Xmm11;
      M128A    Xmm12;
      M128A    Xmm13;
      M128A    Xmm14;
      M128A    Xmm15;
    } XmmSave;
  } CPU_CONTEXT_DUMMYUNIONNAME;

  //
  // Vector registers.
  //

  M128A     VectorRegister[26];
  UINT64    VectorControl;

  //
  // Special debug control registers.
  //

  UINT64    DebugControl;
  UINT64    LastBranchToRip;
  UINT64    LastBranchFromRip;
  UINT64    LastExceptionToRip;
  UINT64    LastExceptionFromRip;
} CONTEXT_AMD64;

STATIC_ASSERT (
               sizeof (CONTEXT_AMD64) == 1232,
               "CONTEXT_AMD64 should be 1232 bytes"
               );

//
// PROCESSOR_ARCHITECTURE_ARM64
//

// For use in RAW_DUMP_SECTION_INFORMATION_CPU_CONTEXT field Architecture.
// From winnt.h: PROCESSOR_ARCHITECTURE_ARM64.
#define PROCESSOR_ARCHITECTURE_ARM64  12

// From winnt.h: ARM64_MAX_BREAKPOINTS.
#define ARM64_MAX_BREAKPOINTS  8

// From winnt.h: ARM64_MAX_WATCHPOINTS.
#define ARM64_MAX_WATCHPOINTS  2

// From winnt.h: ARM64_NT_NEON128.
typedef union {
  struct {
    UINT64    Low;
    INT64     High;
  } CPU_CONTEXT_DUMMYSTRUCTNAME;
  double    D[2];
  float     S[4];
  UINT16    H[8];
  UINT8     B[16];
} ARM64_NT_NEON128;

STATIC_ASSERT (
               sizeof (ARM64_NT_NEON128) == 16,
               "ARM64_NT_NEON128 should be 16 bytes"
               );

// CONTEXT_ARM64: ARM64 processor context for use in RAW_DUMP_SECTION_CPU_CONTEXT data.
// From winnt.h: CONTEXT for _M_ARM64.
typedef struct {
  //
  // Control flags.
  //

  /* +0x000 */ UINT32    ContextFlags;

  //
  // Integer registers
  //

  /* +0x004 */ UINT32    Cpsr;      // NZVF + DAIF + CurrentEL + SPSel
  /* +0x008 */ union {
    struct {
      UINT64                        X0;
      UINT64                        X1;
      UINT64                        X2;
      UINT64                        X3;
      UINT64                        X4;
      UINT64                        X5;
      UINT64                        X6;
      UINT64                        X7;
      UINT64                        X8;
      UINT64                        X9;
      UINT64                        X10;
      UINT64                        X11;
      UINT64                        X12;
      UINT64                        X13;
      UINT64                        X14;
      UINT64                        X15;
      UINT64                        X16;
      UINT64                        X17;
      UINT64                        X18;
      UINT64                        X19;
      UINT64                        X20;
      UINT64                        X21;
      UINT64                        X22;
      UINT64                        X23;
      UINT64                        X24;
      UINT64                        X25;
      UINT64                        X26;
      UINT64                        X27;
      UINT64                        X28;
      /* +0x0f0 */        UINT64    Fp;
      /* +0x0f8 */        UINT64    Lr;
    } CPU_CONTEXT_DUMMYSTRUCTNAME;
    UINT64    X[31];
  } CPU_CONTEXT_DUMMYUNIONNAME;
  /* +0x100 */ UINT64              Sp;
  /* +0x108 */ UINT64              Pc;

  //
  // Floating Point/NEON Registers
  //

  /* +0x110 */ ARM64_NT_NEON128    V[32];
  /* +0x310 */ UINT32              Fpcr;
  /* +0x314 */ UINT32              Fpsr;

  //
  // Debug registers
  //

  /* +0x318 */ UINT32              Bcr[ARM64_MAX_BREAKPOINTS];
  /* +0x338 */ UINT64              Bvr[ARM64_MAX_BREAKPOINTS];
  /* +0x378 */ UINT32              Wcr[ARM64_MAX_WATCHPOINTS];
  /* +0x380 */ UINT64              Wvr[ARM64_MAX_WATCHPOINTS];
  /* +0x390 */
} CONTEXT_ARM64;

STATIC_ASSERT (
               sizeof (CONTEXT_ARM64) == 912,
               "CONTEXT_ARM64 should be 912 bytes"
               );

#undef CPU_CONTEXT_DUMMYSTRUCTNAME
#undef CPU_CONTEXT_DUMMYUNIONNAME
#endif // _included_Guid_OfflineDumpCpuContext_h
