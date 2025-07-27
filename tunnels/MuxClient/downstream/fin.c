#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamFinish(tunnel_t *t, line_t *parent_l)
{
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    muxclient_lstate_t *child_ls  = parent_ls->child_next;

    muxclient_tstate_t *ts  = tunnelGetState(t);
    wid_t               wid = lineGetWID(parent_l);
    if (ts->unsatisfied_lines[wid] == parent_l)
    {
        ts->unsatisfied_lines[wid] = NULL;
    }

    while (child_ls)
    {
        muxclient_lstate_t *temp    = child_ls->child_next;
        line_t             *child_l = child_ls->l;
        muxclientLeaveConnection(child_ls);
        muxclientLinestateDestroy(child_ls);
        tunnelPrevDownStreamFinish(t, child_l);
        child_ls = temp;
    }

    muxclientLinestateDestroy(parent_ls);
    lineDestroy(parent_l);
}
