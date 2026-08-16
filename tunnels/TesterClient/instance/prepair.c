#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelOnPrepair(tunnel_t *t)
{
    testerclient_tstate_t *ts = tunnelGetState(t);
    tunnel_chain_t        *tc = tunnelGetChain(t);

    if (tc->workers_count > kTesterClientMaxWorkers)
    {
        LOGF("TesterClient: supports at most %u workers, but the chain has %u",
             (unsigned int) kTesterClientMaxWorkers, (unsigned int) tc->workers_count);
        startupFailureRecord(1);
        return;
    }

    if (ts->packet_mode && tc->packet_lines == NULL)
    {
        LOGF("TesterClient: packet-mode requires packet lines; add a packet-layer tunnel in the chain");
        startupFailureRecord(1);
        return;
    }
}
