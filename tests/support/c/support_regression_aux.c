/* Auxiliary TU for waterwall.test_support_unit: observes and updates the shared
 * case name and emits the driver-selected deliberate exit/_Exit failure. */
#include "support_regression_aux.h"

void supportCheckCaseFromOtherTU(void)
{
    TEST_EQUAL_TEXT(TEST_FAILURE_EXIT, testCaseName(), "support fixture", "shared case from main");
    testCaseSet("case set in auxiliary TU");
}

void supportFailFromOtherTU(test_failure_policy_t policy)
{
    TEST_REQUIRE(policy, false, "deliberate NDEBUG failure in auxiliary TU");
}
