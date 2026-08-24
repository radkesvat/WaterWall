#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                context;
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (! ts->packet_mode)
    {
        return;
    }

    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(! chain->contains_packet_node))
    {
        LOGF("TesterServer: packet mode finalized chain has no packet-node topology");
        abortProgramNow(1);
    }

    if (UNLIKELY(chain->packet_lines == NULL || wid >= chain->workers_count))
    {
        LOGF("TesterServer: finalized packet chain has invalid worker packet-line geometry for worker %d",
             workerWIDForLog(wid));
        abortProgramNow(1);
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
    if (packet_line == NULL)
    {
        LOGF("TesterServer: finalized packet chain is missing worker packet line %d", workerWIDForLog(wid));
        abortProgramNow(1);
    }

    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid) || lineGetWID(packet_line) != wid ||
                 ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
    {
        LOGF("TesterServer: worker Stop did not run on the exact owner packet line for worker %d",
             workerWIDForLog(wid));
        abortProgramNow(1);
    }

    assert(currentThreadIsEventWorkerWID(wid));
    assert(lineGetWID(packet_line) == wid);
    assert(tunnelchainIsWorkerPacketLine(chain, packet_line));

    /* LinestateDestroy also clears terminal scalar state.  A null stream pool
     * means there are no pooled buffers to recycle, not that this packet line
     * has no state left to settle. */
    testerserverLinestateDestroy(lineGetState(packet_line, t));
}

void testerserverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}
