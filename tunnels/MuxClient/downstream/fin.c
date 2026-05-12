#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamFinish(tunnel_t *t, line_t *parent_l)
{
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    muxclient_lstate_t *child_ls;

    muxclient_tstate_t *ts  = tunnelGetState(t);
    wid_t               wid = lineGetWID(parent_l);
    muxclientForgetParentLine(ts, wid, parent_l);

    lineLock(parent_l);
    parent_ls->parent_finishing = true;
    child_ls                    = parent_ls->child_next;

    while (child_ls)
    {
        muxclient_lstate_t *temp    = child_ls->child_next;
        line_t             *child_l = child_ls->l;

        if (muxclientFlushChildPending(t, parent_l, parent_ls, child_l, child_ls, true))
        {
            muxclientLeaveConnection(child_ls);
            muxclientLinestateDestroy(child_ls);
            tunnelPrevDownStreamFinish(t, child_l);
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnlock(parent_l);
            return;
        }

        child_ls = temp;
    }

    muxclientLinestateDestroy(parent_ls);
    lineDestroy(parent_l);
    lineUnlock(parent_l);
}
