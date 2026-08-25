#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void testerclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                context;
    testerclient_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_mode)
    {
        tunnel_chain_t *chain = tunnelGetChain(t);
        if (chain == NULL || ! chain->finalized)
        {
            return;
        }

        if (UNLIKELY(! chain->contains_packet_node))
        {
            LOGF("TesterClient: packet mode finalized chain has no packet-node topology");
            abortProgramNow(1);
        }

        if (UNLIKELY(chain->packet_lines == NULL || wid >= chain->workers_count))
        {
            LOGF("TesterClient: finalized packet chain has invalid worker packet-line geometry for worker %d",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (packet_line == NULL)
        {
            LOGF("TesterClient: finalized packet chain is missing worker packet line %d", workerWIDForLog(wid));
            abortProgramNow(1);
        }

        if (UNLIKELY(! currentThreadIsEventWorkerWID(wid) || lineGetWID(packet_line) != wid ||
                     ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("TesterClient: worker Stop did not run on the exact owner packet line for worker %d",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        assert(currentThreadIsEventWorkerWID(wid));
        assert(lineGetWID(packet_line) == wid);
        assert(tunnelchainIsWorkerPacketLine(chain, packet_line));

        /* LinestateDestroy also clears terminal scalar state.  A null stream
         * pool means there are no pooled buffers to recycle, not that the
         * packet line state is already zero. */
        testerclientLinestateDestroy(lineGetState(packet_line, t));
        return;
    }

    testerclient_worker_state_t *slot = &ts->workers[wid];
    if (slot->line == NULL || slot->closed)
    {
        return;
    }

    line_t *l = slot->line;
    assert(currentThreadIsEventWorkerWID(wid));
    assert(lineGetWID(l) == wid);

    lineRef(l);
    slot->line            = NULL;
    slot->close_scheduled = true;
    slot->closed          = true;

    testerclient_lstate_t *ls = lineGetState(l, t);
    testerclientLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
    lineUnref(l);
}
