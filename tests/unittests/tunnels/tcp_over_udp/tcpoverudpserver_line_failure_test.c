/* CTest: waterwall.tcpoverudpserver_line_failure_test_unit.
 * Shared real-pair fixture checks admission before service Init, owned service
 * settlement, malformed/control receive and independent KCP queue pressure. */
#include "session_fixture.h"

int main(void)
{
    return tcpOverUdpSessionCases("server");
}
