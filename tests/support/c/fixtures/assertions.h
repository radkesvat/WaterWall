#pragma once

#include "test_assert.h"

/* Compatibility entry points for the line-failure fixtures. Preserve _Exit(1)
 * and the original uint32_t argument conversions; macros keep the call site. */
#define twfSetCase(name)               testCaseSet(name)
#define twfRequire(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)
#define twfRequireEqualU32(actual, expected, message)                                                                  \
    TEST_EQUAL_UINT(TEST_FAILURE_QUICK_EXIT, (uint32_t) (actual), (uint32_t) (expected), message)
#define twfRequireEqualText(actual, expected, message)                                                                 \
    TEST_EQUAL_TEXT(TEST_FAILURE_QUICK_EXIT, actual, expected, message)
