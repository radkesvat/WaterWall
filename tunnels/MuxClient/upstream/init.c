#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamInit(tunnel_t *t, line_t *child_l)
{
    muxclient_tstate_t *ts       = tunnelGetState(t);
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    wid_t               wid      = lineGetWID(child_l);

    if (ts->unsatisfied_lines[wid] == NULL ||
        muxclientCheckConnectionIsExhausted(ts, lineGetState(ts->unsatisfied_lines[wid], t)))
    {
        line_t             *parent_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
        muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

        muxclientLinestateInitialize(parent_ls, parent_l, false,0);

        lineLock(parent_l);
        tunnelNextUpStreamInit(t, parent_l);

        if (! lineIsAlive(parent_l))
        {
            lineUnlock(parent_l);
            muxclientLinestateDestroy(parent_ls);
            lineDestroy(parent_l);

            tunnelPrevDownStreamFinish(t, child_l);
            return;
        }
        lineUnlock(parent_l);

        ts->unsatisfied_lines[wid] = parent_l;
    }
    tunnelPrevDownStreamEst(t, child_l);

    line_t             *parent_l  = ts->unsatisfied_lines[wid];
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    assert(parent_ls->connection_id < CID_MAX);

    muxclientLinestateInitialize(child_ls, child_l, true,++parent_ls->connection_id);
    muxclientJoinConnection(parent_ls, child_ls);
    

    sbuf_t *initpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxclientMakeMuxFrame(initpacket_buf, child_ls->connection_id, kMuxFlagOpen);

    tunnelNextUpStreamPayload(t, parent_l, initpacket_buf);
}
