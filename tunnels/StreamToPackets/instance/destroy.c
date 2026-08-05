#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDestroy(tunnel_t *t)
{
    tunnel_chain_t *chain = tunnelGetChain(t);

    /*
     * Runs after worker work is quiesced. Only this tunnel's own scratch is
     * released: stream lines are borrowed and belong to their own owners, and the
     * worker packet lines live until tunnelchainDestroy().
     */
    streamtopacketsOwnershipDestroy(t);

    if (chain && chain->packet_lines)
    {
        for (wid_t wi = 0; wi < chain->workers_count; ++wi)
        {
            line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wi);
            if (packet_line == NULL)
            {
                continue;
            }

            streamtopackets_lstate_t *ls = lineGetState(packet_line, t);

            streamtopacketsLinestateDestroy(ls);
        }
    }

    tunnelDestroy(t);
}
