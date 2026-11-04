/* CTest: waterwall.tcpoverudpclient_line_failure_test_unit.
 * Shared real-pair fixture retains initialization-refusal, malformed receive,
 * pressure admission, ACK-only Resume and reentrant owner-Finish coverage. */
#include "session_fixture.h"

int main(void)
{
    return tcpOverUdpSessionCases("client");
}
