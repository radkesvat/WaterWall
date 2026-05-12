#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamInit(tunnel_t *t, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    line_t             *parent_l  = muxclientGetParentLineForNewChild(t, child_l);
    if (parent_l == NULL)
    {
        tunnelPrevDownStreamFinish(t, child_l);
        return;
    }
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    assert(parent_ls->connection_id < CID_MAX);

    cid_t new_cid = parent_ls->connection_id + 1;

    muxclientLinestateInitialize(child_ls, child_l, true, new_cid);
    muxclientJoinConnection(parent_ls, child_ls);

    sbuf_t *initpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxclientMakeMuxFrame(initpacket_buf, new_cid, kMuxFlagOpen);

    if (! withLineLockedWithBuf(parent_l, tunnelNextUpStreamPayload, t, initpacket_buf))
    {
        return;
    }

    parent_ls->connection_id = new_cid;
    tunnelPrevDownStreamEst(t, child_l);
}
