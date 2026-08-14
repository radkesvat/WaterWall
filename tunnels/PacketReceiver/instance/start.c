#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelOnStart(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);

    // Reporting is observational; losing this one timer must not affect packet
    // flow or keep any line/resource alive.
    discard sendWorkerMessageTimed(0, packetreceiverReportTimerTask, state->report_after_ms, t, NULL, NULL);
}
