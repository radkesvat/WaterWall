#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPause(tunnel_t *t, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    sbuf_t *pausepacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxclientMakeMuxFrame(pausepacket_buf, child_ls->connection_id, kMuxFlagFlowPause);

    line_t             *parent_line = child_ls->parent->l;
    muxclient_lstate_t *parent_ls   = lineGetState(parent_line, t);

    lineLock(parent_line);
    parent_ls->last_writer = child_l; // update the last writer to the current child
    

    tunnelNextUpStreamPayload(t, parent_line, pausepacket_buf);

    if (! lineIsAlive(parent_line))
    {
        lineUnlock(parent_line);
        return;
    }
    parent_ls->last_writer = NULL; // reset the last writer after sending the payload
    // parent_ls->paused = true;

    lineUnlock(parent_line);

    // tunnelNextUpStreamPause(t, parent_line);
}
