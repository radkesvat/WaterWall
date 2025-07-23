#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{

    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    muxclientMakeMuxFrame(buf, child_ls->connection_id, kMuxFlagData);

    line_t *parent_line = child_ls->parent->l;

    tunnelNextUpStreamPayload(t, parent_line, buf);
}
