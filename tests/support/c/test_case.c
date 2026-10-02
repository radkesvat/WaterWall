/* One executable-wide static case name, shared across translation units.
 * Publish before admitting work and retain it until all case callbacks/threads
 * finish; the API deliberately does not add fixture or thread ownership. */
#include "test_case.h"

static const char *current_case = "<none>";

void testCaseSet(const char *name)
{
    current_case = name;
}

const char *testCaseName(void)
{
    return current_case;
}
