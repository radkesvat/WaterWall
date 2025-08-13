#include "structure.h"

#include "loggers/network_logger.h"

// static void localAsyncCloseLine(worker_t *worker, void *arg1, void *arg2, void *arg3)
// {
//     discard worker;
//     discard arg3;

//     tunnel_t           *t  = arg1;
//     line_t             *l  = arg2;
//     muxclient_lstate_t *ls = lineGetState(l, t);

//     if (lineIsAlive(l))
//     {
//         muxclientLinestateDestroy(ls);
//         tunnelPrevDownStreamFinish(t, l);
//     }
//     lineUnlock(l);
// }

void muxclientTunnelUpStreamFinish(tunnel_t *t, line_t *child_l)
{

    muxclient_tstate_t *ts       = tunnelGetState(t);
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);
    wid_t               wid      = lineGetWID(child_l);

    assert(child_ls->is_child);

    assert(child_ls->parent);
 

    muxclient_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;
    muxclientLeaveConnection(child_ls);

    // if (parent_ls->paused)
    // {
    //     parent_ls->paused = false;
    //     // sbuf_t *resumepacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    //     // muxclientMakeMuxFrame(resumepacket_buf, child_ls->connection_id, kMuxFlagFlowResume);
    //     lineLock(parent_l);
    //     // tunnelNextUpStreamPayload(t, parent_l, resumepacket_buf);
    //     // if (! lineIsAlive(parent_l))
    //     // {
    //     //     muxclientLinestateDestroy(child_ls);
    //     //     lineUnlock(parent_l);
    //     //     return;
    //     // }
    //     tunnelNextUpStreamResume(t, parent_l);
    //     if (! lineIsAlive(parent_l))
    //     {
    //         muxclientLinestateDestroy(child_ls);
    //         lineUnlock(parent_l);
    //         return;
    //     }
    //     lineUnlock(parent_l);
    // }

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxclientMakeMuxFrame(finishpacket_buf, child_ls->connection_id, kMuxFlagClose);
    muxclientLinestateDestroy(child_ls);
    lineLock(parent_l);
    tunnelNextUpStreamPayload(t, parent_l, finishpacket_buf);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        return;
    }
    lineUnlock(parent_l);

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        // If the parent connection is exhausted and has no children, we can close it

        if (ts->unsatisfied_lines[wid] == parent_l)
        {
            ts->unsatisfied_lines[wid] = NULL;
        }
        muxclientLinestateDestroy(parent_ls);
        tunnelNextUpStreamFinish(t, parent_l);
        lineDestroy(parent_l);
    }
}
