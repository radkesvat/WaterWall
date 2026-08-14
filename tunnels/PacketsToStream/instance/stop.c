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

static void packetstostreamCloseWorkerOutputLine(tunnel_t *t, wid_t wid)
{
    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);
    if (packet_line == NULL)
    {
        return;
    }

    packetstostream_lstate_t *ls          = lineGetState(packet_line, t);
    line_t                   *stream_line = ls->line;

    ls->recreate_scheduled = false;
    packetstostreamResetOutputLineState(t, packet_line, ls);

    if (stream_line == NULL || ! lineIsAlive(stream_line))
    {
        return;
    }

    lineLock(stream_line);
    tunnelNextUpStreamFinish(t, stream_line);
    if (lineIsAlive(stream_line))
    {
        lineDestroy(stream_line);
    }
    lineUnlock(stream_line);
}

void packetstostreamTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void packetstostreamTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    // onWorkerStop runs on the worker being stopped, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

    packetstostream_tstate_t *ts = tunnelGetState(t);

    /*
     * PacketsToStream created this normal stream line, so worker shutdown must
     * detach it from packet-line state, finish away from the packet side, and
     * leave it logically dead before the chain destroys its line pools.
     */
    packetstostreamCloseWorkerOutputLine(t, wid);

    if (ts->worker_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timers[wid]);
    }

    if (ts->worker_timeout_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timeout_timers[wid]);
    }
}
