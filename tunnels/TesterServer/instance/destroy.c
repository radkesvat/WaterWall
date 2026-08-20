#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                context;
    testerserver_tstate_t *ts    = tunnelGetState(t);
    tunnel_chain_t        *chain = tunnelGetChain(t);

    if (ts->packet_mode && chain && chain->packet_lines)
    {
        for (wid_t wi = 0; wi < chain->workers_count; ++wi)
        {
            line_t                *packet_line = tunnelchainGetWorkerPacketLine(chain, wi);
            if (packet_line == NULL)
            {
                continue;
            }

            testerserver_lstate_t *ls          = lineGetState(packet_line, t);

            if (ls->read_stream.pool != NULL)
            {
                testerserverLinestateDestroy(ls);
            }
        }
    }

    tunnelDestroy(t);
}
