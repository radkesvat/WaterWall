/* Compile-only C++ boundary of test_assert.h, built by test_support_regression.
 * It exercises macro/type compatibility without adding another runtime case. */
#include "test_assert.h"

/* Compile the public boundary with the project's C++ compiler. */
void supportCppHeaderCheck();

void supportCppHeaderCheck()
{
    testCaseSet("C++ header boundary");
    TEST_REQUIRE(TEST_FAILURE_EXIT, true, "C++ bool");
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, -1, -1, "C++ signed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, 1U, 1U, "C++ unsigned");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, sizeof(int), sizeof(int), "C++ size");
    TEST_EQUAL_POINTER(TEST_FAILURE_EXIT, nullptr, nullptr, "C++ pointer");
    TEST_EQUAL_TEXT(TEST_FAILURE_EXIT, "a", "a", "C++ text");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, nullptr, nullptr, 0, "C++ bytes");
}
