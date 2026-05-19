#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelOnStart(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);

    sendWorkerMessageTimed(0, packetreceiverReportTimerTask, state->report_after_ms, t, NULL, NULL);
}
