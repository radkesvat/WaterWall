#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{

    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    muxclientMakeMuxFrame(buf, child_ls->connection_id, kMuxFlagData);

    line_t *parent_line = child_ls->parent->l;

    muxclient_lstate_t *parent_ls = lineGetState(parent_line, t);

    lineLock(parent_line);
    parent_ls->last_writer = child_l; // update the last writer to the current child

    tunnelNextUpStreamPayload(t, parent_line, buf);

    if (lineIsAlive(parent_line))
    {
        parent_ls->last_writer = NULL; // reset the last writer after sending the payload
    }
    lineUnlock(parent_line);
}
