#include "structure.h"

#include "loggers/network_logger.h"

static void packetstostreamDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

/*
 * A finalized packet chain has exactly one persistent packet line per worker.
 * Startup rollback can reach the lifecycle surface before finalization, in
 * which case there is no worker-local state to settle yet.
 */
static line_t *packetstostreamGetWorkerPacketLineForStop(tunnel_t *t, wid_t wid)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! chain->finalized)
    {
        return NULL;
    }

    if (UNLIKELY(! chain->contains_packet_node))
    {
        LOGF("PacketsToStream: finalized chain lost its required packet topology");
        abortProgramNow(1);
    }

    if (UNLIKELY(chain->packet_lines == NULL || wid >= chain->workers_count))
    {
        LOGF("PacketsToStream: finalized packet chain has invalid worker %u packet-line geometry", (unsigned int) wid);
        abortProgramNow(1);
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
    if (UNLIKELY(packet_line == NULL || ! currentThreadIsEventWorkerWID(wid) || lineGetWID(packet_line) != wid ||
                 ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
    {
        LOGF("PacketsToStream: invalid finalized packet-line ownership on worker %u", (unsigned int) wid);
        abortProgramNow(1);
    }

    return packet_line;
}

static void packetstostreamCloseWorkerOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    line_t *stream_line = ls->line;

    ls->recreate_scheduled = false;
    packetstostreamResetOutputLineState(t, packet_line, ls);

    if (stream_line == NULL || ! lineIsAlive(stream_line))
    {
        return;
    }

    lineRef(stream_line);
    tunnelNextUpStreamFinish(t, stream_line);
    if (lineIsAlive(stream_line))
    {
        lineDestroy(stream_line);
    }
    lineUnref(stream_line);
}

void packetstostreamTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void packetstostreamTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timers[wid]);
    }

    if (ts->worker_timeout_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timeout_timers[wid]);
    }
}

void packetstostreamTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    line_t *packet_line = packetstostreamGetWorkerPacketLineForStop(t, wid);
    if (packet_line == NULL)
    {
        return;
    }

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    packetstostreamCloseWorkerOutputLine(t, packet_line, ls);

    /* The buffer stream is owned by this packet line's worker pool. It must be
     * released here, before node-manager teardown retires that pool. */
    if (ls->read_stream.pool != NULL)
    {
        packetstostreamLinestateDestroy(ls);
    }
}
