#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{

    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    if (child_ls->parent->parent_finishing)
    {
        lineReuseBuffer(child_l, buf);
        return;
    }

    const bool send_open = ! child_ls->open_frame_sent;

    const uint32_t      payload_length = sbufGetLength(buf);
    sbuf_t             *encoded        = NULL;
    mux_encode_result_t encode_result =
        muxEncodeChildPayload(lineGetBufferPool(child_l), buf, child_ls->connection_id, send_open, &encoded);
    if (UNLIKELY(encode_result != kMuxEncodeSuccess))
    {
        // buf is already recycled; close only this child and leave the parent and its siblings running
        LOGE("MuxClient: cid %u payload of %u bytes cannot be encoded into MUX frames, closing this child",
             child_ls->connection_id,
             payload_length);
        muxclient_lstate_t *parent_ls = child_ls->parent;
        muxclientCloseChildKeepParent(t, tunnelGetState(t), parent_ls->l, parent_ls, child_ls, true);
        return;
    }

    // published only after the encoding succeeded, so a failed child never claims to have opened its cid
    child_ls->open_frame_sent = true;

    line_t *parent_line = child_ls->parent->l;

    muxclient_lstate_t *parent_ls = lineGetState(parent_line, t);

    lineLock(parent_line);
    parent_ls->last_writer = child_l; // update the last writer to the current child

    tunnelNextUpStreamPayload(t, parent_line, encoded);

    if (lineIsAlive(parent_line))
    {
        parent_ls->last_writer = NULL; // reset the last writer after sending the payload
    }
    lineUnlock(parent_line);
}
