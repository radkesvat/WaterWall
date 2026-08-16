#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

static void muxclientCloseSelectedParentLine(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid, line_t *parent_l)
{
    assert(lineGetWID(parent_l) == wid);

    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    if (UNLIKELY(parent_ls->children_count != 0 || parent_ls->child_next != NULL))
    {
        LOGF("MuxClient: worker stop observed %u borrowed child line(s); source owners must drain first",
             parent_ls->children_count);
        abortProgramNow(1);
    }

    parent_ls->parent_finishing = true;
    muxclientCloseIdleExhaustedParentLine(t, ts, wid, parent_l, parent_ls);
}

void muxclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    muxclient_tstate_t *ts = tunnelGetState(t);
    if (ts->concurrency_mode != kConcurrencyModeFixedConnectionsCount)
    {
        line_t *parent_l           = ts->unsatisfied_lines[wid];
        ts->unsatisfied_lines[wid] = NULL;
        if (parent_l != NULL)
        {
            muxclientCloseSelectedParentLine(t, ts, wid, parent_l);
        }
        return;
    }

    for (uint32_t index = 0; index < ts->fixed_connections_count; ++index)
    {
        const size_t slot_index = ((size_t) wid * (size_t) ts->fixed_connections_count) + (size_t) index;
        line_t      *parent_l   = ts->fixed_parent_lines[slot_index];
        if (parent_l == NULL)
        {
            continue;
        }

        for (uint32_t other = index + 1; other < ts->fixed_connections_count; ++other)
        {
            const size_t other_slot = ((size_t) wid * (size_t) ts->fixed_connections_count) + (size_t) other;
            if (UNLIKELY(ts->fixed_parent_lines[other_slot] == parent_l))
            {
                LOGF("MuxClient: duplicate parent in fixed selection slots");
                abortProgramNow(1);
            }
        }

        ts->fixed_parent_lines[slot_index] = NULL;
        muxclientCloseSelectedParentLine(t, ts, wid, parent_l);
    }
}
