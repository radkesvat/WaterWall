/* Direct subprocess fixture: NDEBUG, one context across two TUs, operand
 * evaluation, caller-owned TEST_CHECK status and explicit exit/_Exit policy. No WaterWall/runtime dependency.
 * CTest: waterwall.test_support_unit (runs this fixture's deliberate failures). */
#include "support_regression_aux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NDEBUG
#error "The assertion regression must also exercise an NDEBUG caller in Debug"
#endif

static void atExitMarker(void)
{
    puts("atexit marker");
}

static void singleEvaluation(void)
{
    int a = 0, b = 0, size_calls = 0;
    TEST_REQUIRE(TEST_FAILURE_EXIT, TEST_CHECK(++size_calls == 1, "nonfatal success"), "check result");
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, size_calls, 1, "nonfatal operand evaluated once");
    size_calls = 0;
    TEST_REQUIRE(TEST_FAILURE_EXIT, ++a == 1, "boolean operand evaluated once");
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, ++a, ++b + 1, "signed operands evaluated once");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, ++a, ++b + 1, "unsigned operands evaluated once");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, ++a, ++b + 1, "size operands evaluated once");
    const char *texts[]      = {"same", "same"};
    size_t      actual_index = 0, expected_index = 0;
    TEST_EQUAL_POINTER(
        TEST_FAILURE_EXIT, &texts[actual_index++], &texts[expected_index++], "pointer operands evaluated once");
    TEST_EQUAL_TEXT(TEST_FAILURE_EXIT, texts[actual_index++], texts[expected_index++], "text operands evaluated once");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, actual_index, 2, "pointer and text actual operands evaluated once");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, expected_index, 2, "pointer and text expected operands evaluated once");
    actual_index = expected_index = 0;
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT,
                     texts[actual_index++],
                     texts[expected_index++],
                     ++size_calls,
                     "byte operands and length evaluated once");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, NULL, NULL, 0, "empty buffers need no storage");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 a == 4 && b == 3 && actual_index == 1 && expected_index == 1 && size_calls == 1,
                 "an operand was evaluated more than once");
}

int main(int argc, char **argv)
{
    testCaseSet("support fixture");
    supportCheckCaseFromOtherTU();
    TEST_EQUAL_TEXT(TEST_FAILURE_EXIT, testCaseName(), "case set in auxiliary TU", "shared case from auxiliary TU");
    testCaseSet("support fixture");
    singleEvaluation();
    if (argc != 2)
        return 2;
    if (strcmp(argv[1], "pass") == 0)
        return 0;
    if (strcmp(argv[1], "check") == 0)
    {
        int  calls  = 0;
        bool result = TEST_CHECK(++calls == 2, "deliberate nonfatal failure");
        TEST_REQUIRE(TEST_FAILURE_EXIT, ! result && calls == 1, "nonfatal failure result and evaluation");
        puts("continuation marker");
        return 2; /* The suite, not the reporter, selects its sentinel verdict. */
    }
    TEST_EQUAL_INT(TEST_FAILURE_EXIT, atexit(atExitMarker), 0, "register policy observation");
    fputs("buffered stdout marker\n", stdout);
    if (strcmp(argv[1], "exit") == 0)
        supportFailFromOtherTU(TEST_FAILURE_EXIT);
    if (strcmp(argv[1], "quick") == 0)
        supportFailFromOtherTU(TEST_FAILURE_QUICK_EXIT);
    if (strcmp(argv[1], "int") == 0)
        TEST_EQUAL_INT(TEST_FAILURE_QUICK_EXIT, -7, 2, "signed comparison");
    if (strcmp(argv[1], "uint") == 0)
        TEST_EQUAL_UINT(TEST_FAILURE_QUICK_EXIT, UINTMAX_MAX, 2, "unsigned comparison");
    if (strcmp(argv[1], "size") == 0)
        TEST_EQUAL_SIZE(TEST_FAILURE_QUICK_EXIT, 9, 2, "size comparison");
    if (strcmp(argv[1], "pointer") == 0)
        TEST_EQUAL_POINTER(TEST_FAILURE_QUICK_EXIT, argv, NULL, "pointer comparison");
    if (strcmp(argv[1], "text") == 0)
        TEST_EQUAL_TEXT(TEST_FAILURE_QUICK_EXIT, "actual", "expected", "text comparison");
    if (strcmp(argv[1], "bytes") == 0)
    {
        unsigned char actual[1024] = {0}, expected[1024] = {0};
        actual[17] = 0xa5;
        TEST_EQUAL_BYTES(TEST_FAILURE_QUICK_EXIT, actual, expected, sizeof(actual), "byte comparison");
    }
    return 2;
}
