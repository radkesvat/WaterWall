#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamInit(tunnel_t *t, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    line_t             *parent_l = muxclientGetParentLineForNewChild(t, child_l);
    if (parent_l == NULL)
    {
        tunnelPrevDownStreamFinish(t, child_l);
        return;
    }
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    assert(parent_ls->connection_id < kMuxCidMax);

    mux_cid_t new_cid = parent_ls->connection_id + 1;

    muxclientLinestateInitialize(t, child_ls, child_l, true, new_cid);
    muxclientJoinConnection(parent_ls, child_ls);
    parent_ls->connection_id = new_cid;

    child_ls->source_starting = true;
    lineRef(parent_l);
    lineRef(child_l);
    tunnelPrevDownStreamEst(t, child_l);
    if (lineIsAlive(child_l))
    {
        child_ls = lineGetState(child_l, t);
        if (child_ls->is_child)
        {
            child_ls->source_starting = false;
            if (lineIsAlive(parent_l) && child_ls->parent == parent_ls && ! parent_ls->parent_finishing &&
                parent_ls->parent_state->output.sources_throttled)
            {
                discard muxclientPauseChildSource(t, parent_l, child_ls, false, true);
            }
        }
    }
    lineUnref(child_l);
    lineUnref(parent_l);
}
