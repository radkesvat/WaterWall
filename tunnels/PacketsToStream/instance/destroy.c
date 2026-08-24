#include "structure.h"

#include "loggers/network_logger.h"

static void packetstostreamVerifyPacketStateDrained(tunnel_t *t)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! chain->finalized)
    {
        return;
    }

    if (UNLIKELY(! chain->contains_packet_node))
    {
        LOGF("PacketsToStream: finalized chain lost its required packet topology");
        abortProgramNow(1);
    }

    if (UNLIKELY(chain->packet_lines == NULL))
    {
        LOGF("PacketsToStream: finalized packet chain has no packet-line array");
        abortProgramNow(1);
    }

    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (UNLIKELY(packet_line == NULL))
        {
            LOGF("PacketsToStream: finalized packet chain is missing worker %u's packet line", (unsigned int) wid);
            abortProgramNow(1);
        }

        if (UNLIKELY(lineGetWID(packet_line) != wid || ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("PacketsToStream: finalized chain has a non-owner packet line in worker %u slot during Destroy",
                 (unsigned int) wid);
            abortProgramNow(1);
        }

        /* Do not destroy this state here: Destroy runs after worker-local
         * pools are retired. Reading the pool pointer is enough to diagnose an
         * omitted owner-worker drain without dereferencing that retired pool. */
        packetstostream_lstate_t *ls = lineGetState(packet_line, t);
        if (UNLIKELY(ls->read_stream.pool != NULL))
        {
            LOGF("PacketsToStream: finalized packet line on worker %u retained undrained line state",
                 (unsigned int) wid);
            abortProgramNow(1);
        }
    }
}

void packetstostreamTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /* onWorkerStop settles packet-line state while its exact owner pool is
     * alive. A pre-finalization rollback has no packet state to inspect. */
    packetstostreamVerifyPacketStateDrained(t);

    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_timers != NULL)
    {
        memoryFree(ts->worker_timers);
        ts->worker_timers = NULL;
    }

    if (ts->worker_timeout_timers != NULL)
    {
        memoryFree(ts->worker_timeout_timers);
        ts->worker_timeout_timers = NULL;
    }

    tunnelDestroy(t);
}
