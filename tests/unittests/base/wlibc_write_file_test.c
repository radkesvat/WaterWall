/*
 * Covers: wlibc write file; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.wlibc_write_file_unit
 */
#include "wlibc.h"
#include "wwapi.h"

int main(void)
{
    static const char data[] = "flush failure";

    if (writeFile("/dev/full", data, sizeof(data) - 1U))
    {
        fprintf(stderr, "writeFile reported success after fclose failed\n");
        return 1;
    }

    return 0;
}
