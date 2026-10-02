/*
 * Covers: Verifies the POSIX select backend rejects descriptors outside `fd_set` bounds while accepting
 * the highest valid descriptor.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testSelectFdRange
 * Checks: Assertion labels include: select backend accepted a negative descriptor; invalid descriptor
 * initialized the select backend; select backend accepted FD_SETSIZE; out-of-range descriptor
 * initialized the select backend
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.select_fd_range_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "iowatcher.h"
#include "wsocket.h"


static void testSelectFdRange(void)
{
    wloop_t loop = {0};

    require(iowatcherAddEvent(&loop, -1, WW_READ) == -ERANGE, "select backend accepted a negative descriptor");
    require(loop.iowatcher == NULL, "invalid descriptor initialized the select backend");

    require(iowatcherAddEvent(&loop, FD_SETSIZE, WW_READ) == -ERANGE, "select backend accepted FD_SETSIZE");
    require(loop.iowatcher == NULL, "out-of-range descriptor initialized the select backend");

    require(iowatcherAddEvent(&loop, FD_SETSIZE - 1, WW_READ) == 0, "select backend rejected FD_SETSIZE - 1");
    require(loop.iowatcher != NULL, "valid descriptor did not initialize the select backend");
    require(iowatcherDelEvent(&loop, FD_SETSIZE, WW_READ) == -ERANGE, "select backend deletion accepted FD_SETSIZE");
    require(iowatcherDelEvent(&loop, FD_SETSIZE - 1, WW_READ) == 0, "select backend failed to delete FD_SETSIZE - 1");
    require(iowatcherCleanUp(&loop) == 0, "select backend cleanup failed");
    require(loop.iowatcher == NULL, "select backend cleanup retained its context");
}

int main(void)
{
    testCaseSet("select_fd_range_test");
    testSelectFdRange();
    return 0;
}
