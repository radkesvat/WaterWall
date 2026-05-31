#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->line_complete && ! ls->failed)
    {
        if (ls->received_reports >= ls->expected_reports && ls->sender_finished && ls->receiver_finished)
        {
            speedtestclientFinishFromDownstreamFinish(t, l, true, NULL);
            return;
        }

        speedtestclientFinishFromDownstreamFinish(t, l, false, "transport closed before the speed test completed");
        return;
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
}
