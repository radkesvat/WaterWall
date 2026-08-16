#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void speedtestclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                   context;
    speedtestclient_tstate_t *state = tunnelGetState(t);
    atomicStoreRelaxed(&state->stopping, true);
}

void speedtestclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    speedtestclient_tstate_t *state         = tunnelGetState(t);
    const uint32_t            workers_count = tunnelGetChain(t)->workers_count;

    for (uint32_t stream_id = wid; stream_id < state->connection_count; stream_id += workers_count)
    {
        line_t *l = state->owned_lines[stream_id];
        if (l == NULL)
        {
            continue;
        }

        assert(lineGetWID(l) == wid);
        speedtestclient_lstate_t *ls                 = lineGetState(l, t);
        const bool                upstream_init_sent = ls->upstream_init_sent;

        lineLock(l);
        state->owned_lines[stream_id] = NULL;
        speedtestclientLinestateDestroy(ls);
        if (upstream_init_sent && lineIsAlive(l))
        {
            tunnelNextUpStreamFinish(t, l);
        }
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }
        lineUnlock(l);
    }
}
