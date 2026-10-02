#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamInit(tunnel_t *t, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    // Selection can close/refill a parent and re-enter the source. Publish the
    // borrowed child's state before those callbacks, even before it has a CID.
    muxclientLinestateInitialize(t, child_ls, child_l, true, 0);
    lineRef(child_l);
    line_t             *parent_l = muxclientGetParentLineForNewChild(t, child_l);
    if (! lineIsAlive(child_l) || child_ls->l == NULL)
    {
        lineUnref(child_l);
        return;
    }
    if (parent_l == NULL)
    {
        muxclientLinestateDestroy(child_ls);
        tunnelPrevDownStreamFinish(t, child_l);
        lineUnref(child_l);
        return;
    }
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    assert(parent_ls->connection_id < kMuxCidMax);

    mux_cid_t new_cid = parent_ls->connection_id + 1;

    child_ls->connection_id = new_cid;
    muxclientJoinConnection(parent_ls, child_ls);
    parent_ls->connection_id = new_cid;

    child_ls->source_starting = true;
    lineRef(parent_l);
    tunnelPrevDownStreamEst(t, child_l);
    if (lineIsAlive(child_l) && ((muxclient_lstate_t *) lineGetState(child_l, t))->is_child)
        muxclientChildSourceStarted(t, child_l);
    lineUnref(child_l);
    lineUnref(parent_l);
}
