#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard         context;
    tunnel_chain_t *chain = tunnelGetChain(t);

    if (chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(chain->packet_lines == NULL || wid >= chain->workers_count))
    {
        LOGF("JunkDatagramSender: finalized packet chain has invalid worker packet-line geometry for worker %d",
             workerWIDForLog(wid));
        abortProgramNow(1);
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
    if (UNLIKELY(chain->contains_packet_node != (packet_line != NULL)))
    {
        LOGF("JunkDatagramSender: finalized packet topology disagrees with worker slot %d", workerWIDForLog(wid));
        abortProgramNow(1);
    }
    if (packet_line == NULL)
    {
        return;
    }

    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid) || lineGetWID(packet_line) != wid ||
                 ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
    {
        LOGF("JunkDatagramSender: worker Stop did not run on the exact owner packet line for worker %d",
             workerWIDForLog(wid));
        abortProgramNow(1);
    }

    junkdatagramsenderLinestateDestroy(lineGetState(packet_line, t));
}

void junkdatagramsenderTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}
