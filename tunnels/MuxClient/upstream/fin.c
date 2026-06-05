#include "structure.h"

#include "loggers/network_logger.h"

static void muxclientCloseOwnedParentLineFromUpstreamFinish(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid,
                                                            line_t *parent_l, muxclient_lstate_t *parent_ls)
{
    muxclientForgetParentLine(ts, wid, parent_l);

    muxclientLinestateDestroy(parent_ls);
    tunnelNextUpStreamFinish(t, parent_l);

    if (lineIsAlive(parent_l))
    {
        lineDestroy(parent_l);
    }
}

void muxclientTunnelUpStreamFinish(tunnel_t *t, line_t *child_l)
{

    muxclient_tstate_t *ts       = tunnelGetState(t);
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    wid_t               wid      = lineGetWID(child_l);

    assert(child_ls->is_child);

    assert(child_ls->parent);

    muxclient_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;
    cid_t               cid       = child_ls->connection_id;
    muxclientLeaveConnection(child_ls);

    if (parent_ls->parent_finishing)
    {
        muxclientLinestateDestroy(child_ls);
        return;
    }

    if (! muxclientResumeParentInputForChild(t, parent_l, parent_ls, child_ls))
    {
        muxclientLinestateDestroy(child_ls);
        return;
    }

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxclientMakeMuxFrame(finishpacket_buf, cid, kMuxFlagClose);
    muxclientLinestateDestroy(child_ls);

    if (! withLineLockedWithBuf(parent_l, tunnelNextUpStreamPayload, t, finishpacket_buf))
    {
        return;
    }

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseOwnedParentLineFromUpstreamFinish(t, ts, wid, parent_l, parent_ls);
    }
}
