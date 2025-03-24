#ifndef __included_OfflineDumpTest_h
#define __included_OfflineDumpTest_h

#define ALL_TESTS(x) \
    x(RedactionScratchBufferLengthTest) \
    x(SparseBitmapTest) \

#define TestAssert(   condition)            ((condition) \
    ? (void)0    \
    : TestErr("%a(%u) : ASSERT(%a)",       __FILE__, __LINE__, #condition))

#define TestAssertFmt(condition, fmt, ...)  ((condition) \
    ? (void)0    \
    : TestErr("%a(%u) : ASSERT(%a): " fmt, __FILE__, __LINE__, #condition, __VA_ARGS__))

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void
TestMsg(char const* fmt, ...);

void
TestErr(char const* fmt, ...);

#define DECLARE_TEST(TestName) void TestName(void);
ALL_TESTS(DECLARE_TEST)
#undef DECLARE_TEST

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // __included_OfflineDumpTest_h
