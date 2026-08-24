#include "structure.h"

#include "loggers/network_logger.h"

static bool testerserverLinestateIsZeroed(const testerserver_lstate_t *ls)
{
    const uint8_t *state = (const uint8_t *) ls;
    const size_t   size  = tunnelGetCorrectAlignedLineStateSize(sizeof(*ls));

    for (size_t offset = 0; offset < size; ++offset)
    {
        if (state[offset] != 0)
        {
            return false;
        }
    }

    return true;
}

static void testerserverVerifyPacketStateDrained(tunnel_t *t)
{
    testerserver_tstate_t *ts    = tunnelGetState(t);
    tunnel_chain_t        *chain = tunnelGetChain(t);
    if (! ts->packet_mode || chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(! chain->contains_packet_node))
    {
        LOGF("TesterServer: packet mode finalized chain has no packet-node topology during Destroy");
        abortProgramNow(1);
    }

    if (UNLIKELY(chain->packet_lines == NULL))
    {
        LOGF("TesterServer: finalized packet chain is missing packet-line slots during Destroy");
        abortProgramNow(1);
    }

    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (packet_line == NULL)
        {
            LOGF("TesterServer: finalized packet chain is missing worker packet line %d during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        if (UNLIKELY(lineGetWID(packet_line) != wid || ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("TesterServer: finalized chain has a non-owner packet line in worker %d slot during Destroy",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        testerserver_lstate_t *ls = lineGetState(packet_line, t);
        if (UNLIKELY(! testerserverLinestateIsZeroed(ls)))
        {
            LOGF("TesterServer: finalized packet line on worker %d retained undrained line state",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }
}

void testerserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /* Packet state is settled by onWorkerStop before worker-local pools are
     * released. A rollback that bypasses owner callbacks cannot have accepted
     * packet payload, so Destroy deliberately avoids post-worker pool access. */
    testerserverVerifyPacketStateDrained(t);

    tunnelDestroy(t);
}
