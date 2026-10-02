#ifndef WW_TEST_ASSERT_H
#define WW_TEST_ASSERT_H

#include "test_case.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Publish the fatal edge to optimized callers as well as the implementation. */
#if defined(__cplusplus)
#define WW_TEST_NORETURN [[noreturn]]
#elif defined(_MSC_VER) && ! defined(__clang__)
#define WW_TEST_NORETURN __declspec(noreturn)
#else
#define WW_TEST_NORETURN _Noreturn
#endif

    /* Explicit failure policy: EXIT runs atexit handlers and flushes streams;
     * QUICK_EXIT uses _Exit, preserving failure-injection/death-test boundaries.
     * Neither policy calls runtime shutdown or performs fixture teardown. */
    typedef enum test_failure_policy_e
    {
        TEST_FAILURE_EXIT,
        TEST_FAILURE_QUICK_EXIT
    } test_failure_policy_t;

    /* Always active under NDEBUG. Comparison operands are evaluated once, with no
     * ordering promise between them. Text operands must be valid C strings, byte
     * operands readable for size bytes (NULL is valid only when size is zero).
     * Diagnostics include the case, original call site and explanatory message. */
    WW_TEST_NORETURN void testRequireFailedAt(test_failure_policy_t policy, const char *expression, const char *message,
                                              const char *file, int line);
    /* Report without exiting for suites that accumulate failures or deliberately
     * return a sentinel status. The caller owns continuation and final verdict. */
    bool testCheckAt(bool condition, const char *expression, const char *message, const char *file, int line);
    void testEqualIntAt(test_failure_policy_t policy, intmax_t actual, intmax_t expected, const char *message,
                        const char *file, int line);
    void testEqualUintAt(test_failure_policy_t policy, uintmax_t actual, uintmax_t expected, const char *message,
                         const char *file, int line);
    void testEqualSizeAt(test_failure_policy_t policy, size_t actual, size_t expected, const char *message,
                         const char *file, int line);
    void testEqualPointerAt(test_failure_policy_t policy, const void *actual, const void *expected, const char *message,
                            const char *file, int line);
    void testEqualTextAt(test_failure_policy_t policy, const char *actual, const char *expected, const char *message,
                         const char *file, int line);
    void testEqualBytesAt(test_failure_policy_t policy, const void *actual, const void *expected, size_t size,
                          const char *message, const char *file, int line);

#ifdef __cplusplus
}
#endif

#define TEST_REQUIRE(policy, condition, message)                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        test_failure_policy_t ww_test_failure_policy_      = (policy);                                                 \
        bool                  ww_test_condition_value_     = (condition);                                              \
        const char           *ww_test_requirement_message_ = (message);                                                \
        if (! ww_test_condition_value_)                                                                                \
            testRequireFailedAt(                                                                                       \
                ww_test_failure_policy_, #condition, ww_test_requirement_message_, __FILE__, __LINE__);                \
    } while (0)
#define TEST_CHECK(condition, message) testCheckAt((condition), #condition, (message), __FILE__, __LINE__)
#define TEST_EQUAL_INT(policy, actual, expected, message)                                                              \
    testEqualIntAt((policy), (actual), (expected), (message), __FILE__, __LINE__)
#define TEST_EQUAL_UINT(policy, actual, expected, message)                                                             \
    testEqualUintAt((policy), (actual), (expected), (message), __FILE__, __LINE__)
#define TEST_EQUAL_SIZE(policy, actual, expected, message)                                                             \
    testEqualSizeAt((policy), (actual), (expected), (message), __FILE__, __LINE__)
#define TEST_EQUAL_POINTER(policy, actual, expected, message)                                                          \
    testEqualPointerAt((policy), (actual), (expected), (message), __FILE__, __LINE__)
#define TEST_EQUAL_TEXT(policy, actual, expected, message)                                                             \
    testEqualTextAt((policy), (actual), (expected), (message), __FILE__, __LINE__)
#define TEST_EQUAL_BYTES(policy, actual, expected, size, message)                                                      \
    testEqualBytesAt((policy), (actual), (expected), (size), (message), __FILE__, __LINE__)

#endif
