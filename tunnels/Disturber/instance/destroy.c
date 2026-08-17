#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard         context;
    tunnel_chain_t *chain = tunnelGetChain(t);

    if (chain != NULL && chain->packet_lines != NULL)
    {
        for (wid_t wi = 0; wi < chain->workers_count; ++wi)
        {
            line_t             *packet_line = tunnelchainGetWorkerPacketLine(chain, wi);
            if (packet_line == NULL)
            {
                continue;
            }

            disturber_lstate_t *ls          = lineGetState(packet_line, t);

            disturberLinestateDestroy(ls);
        }
    }

    tunnelDestroy(t);
}
