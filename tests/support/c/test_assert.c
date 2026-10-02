/* Always-active test diagnostics and explicit exit/_Exit policies. TEST_CHECK
 * returns its verdict so callers retain their own continuation/exit behavior.
 * No runtime dependencies or fixture teardown; see test_assert.h for operands. */
#include "test_assert.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void failurePrefix(const char *message, const char *file, int line)
{
    fprintf(stderr, "FAIL [%s] %s:%d: %s", testCaseName(), file, line, message);
}

static WW_TEST_NORETURN void failureExit(test_failure_policy_t policy)
{
    fputc('\n', stderr);
    fflush(stderr);
    if (policy == TEST_FAILURE_QUICK_EXIT)
        _Exit(1);
    exit(1);
}

WW_TEST_NORETURN void testRequireFailedAt(test_failure_policy_t policy, const char *expression, const char *message,
                                          const char *file, int line)
{
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected true, got false: %s)", expression);
    failureExit(policy);
}

bool testCheckAt(bool condition, const char *expression, const char *message, const char *file, int line)
{
    if (condition)
        return true;
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected true, got false: %s)\n", expression);
    fflush(stderr);
    return false;
}

void testEqualIntAt(test_failure_policy_t policy, intmax_t actual, intmax_t expected, const char *message,
                    const char *file, int line)
{
    if (actual == expected)
        return;
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected %" PRIdMAX ", got %" PRIdMAX ")", expected, actual);
    failureExit(policy);
}

void testEqualUintAt(test_failure_policy_t policy, uintmax_t actual, uintmax_t expected, const char *message,
                     const char *file, int line)
{
    if (actual == expected)
        return;
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected %" PRIuMAX ", got %" PRIuMAX ")", expected, actual);
    failureExit(policy);
}

void testEqualSizeAt(test_failure_policy_t policy, size_t actual, size_t expected, const char *message,
                     const char *file, int line)
{
    testEqualUintAt(policy, actual, expected, message, file, line);
}

void testEqualPointerAt(test_failure_policy_t policy, const void *actual, const void *expected, const char *message,
                        const char *file, int line)
{
    if (actual == expected)
        return;
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected %p, got %p)", (void *) expected, (void *) actual);
    failureExit(policy);
}

void testEqualTextAt(test_failure_policy_t policy, const char *actual, const char *expected, const char *message,
                     const char *file, int line)
{
    if (strcmp(actual, expected) == 0)
        return;
    failurePrefix(message, file, line);
    fprintf(stderr, " (expected \"%s\", got \"%s\")", expected, actual);
    failureExit(policy);
}

void testEqualBytesAt(test_failure_policy_t policy, const void *actual, const void *expected, size_t size,
                      const char *message, const char *file, int line)
{
    const unsigned char *got  = actual;
    const unsigned char *want = expected;
    for (size_t i = 0; i < size; ++i)
    {
        if (got[i] == want[i])
            continue;
        failurePrefix(message, file, line);
        fprintf(stderr,
                " (first difference at offset %zu of %zu: expected 0x%02x, got 0x%02x;",
                i,
                size,
                (unsigned int) want[i],
                (unsigned int) got[i]);
        /* At most eight bytes starting at the mismatch, independent of size. */
        size_t shown = size - i < 8 ? size - i : 8;
        fputs(" expected", stderr);
        for (size_t j = 0; j < shown; ++j)
            fprintf(stderr, " %02x", (unsigned int) want[i + j]);
        fputs("; got", stderr);
        for (size_t j = 0; j < shown; ++j)
            fprintf(stderr, " %02x", (unsigned int) got[i + j]);
        fputc(')', stderr);
        failureExit(policy);
    }
}
