#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamFinish(tunnel_t *t, line_t *child_l)
{

    muxclient_tstate_t *ts       = tunnelGetState(t);
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    assert(child_ls->parent);

    muxclient_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;

    // the previous side sent us Finish, so nothing may be reflected back toward it
    muxclientCloseChildKeepParent(t, ts, parent_l, parent_ls, child_ls, false);
}
