#include "structure.h"

#include "loggers/network_logger.h"


void muxserverTunnelDownStreamPause(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    sbuf_t *pausepacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxserverMakeMuxFrame(pausepacket_buf, child_ls->connection_id, kMuxFlagFlowPause);

    line_t             *parent_line = child_ls->parent->l;
    muxserver_lstate_t *parent_ls   = lineGetState(parent_line, t);

    lineLock(parent_line);
    tunnelPrevDownStreamPayload(t, parent_line, pausepacket_buf);

    if (! lineIsAlive(parent_line))
    {
        lineUnlock(parent_line);
        return;
    }
    lineUnlock(parent_line);

    parent_ls->paused = true;
    tunnelPrevDownStreamPause(t, parent_line);
}
