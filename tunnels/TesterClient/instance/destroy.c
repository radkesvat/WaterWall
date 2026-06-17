#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDestroy(tunnel_t *t)
{
    testerclient_tstate_t *ts    = tunnelGetState(t);
    tunnel_chain_t        *chain = tunnelGetChain(t);

    if (ts->packet_mode && chain && chain->packet_lines)
    {
        for (wid_t wi = 0; wi < chain->workers_count; ++wi)
        {
            line_t                *packet_line = tunnelchainGetWorkerPacketLine(chain, wi);
            testerclient_lstate_t *ls          = lineGetState(packet_line, t);

            if (ls->read_stream.pool != NULL)
            {
                testerclientLinestateDestroy(ls);
            }
        }
    }

    addresscontextReset(&ts->initial_dest_context);
    tunnelDestroy(t);
}
