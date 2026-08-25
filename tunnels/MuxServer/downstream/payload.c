#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamPayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{

    muxserver_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    if (child_ls->close_state != kMuxServerChildCloseOpen)
    {
        lineReuseBuffer(child_l, buf);
        return;
    }

    assert(child_ls->parent != NULL);
    if (child_ls->parent->parent_finishing)
    {
        lineReuseBuffer(child_l, buf);
        return;
    }

    const uint32_t payload_length = sbufGetLength(buf);
    if (payload_length != 0 && child_ls->child_slot_reserved)
    {
        muxserverRefreshChildIdle(t, child_ls);
    }
    sbuf_t             *encoded = NULL;
    mux_encode_result_t encode_result =
        muxEncodeChildPayload(lineGetBufferPool(child_l), buf, child_ls->connection_id, false, &encoded);
    if (UNLIKELY(encode_result != kMuxEncodeSuccess))
    {
        // buf is already recycled; close only this child and leave the parent and its siblings running
        LOGE("MuxServer: cid %u payload of %u bytes cannot be encoded into MUX frames, closing this child",
             child_ls->connection_id,
             payload_length);
        muxserver_lstate_t *parent_ls = child_ls->parent;
        muxserverCloseChildKeepParent(t, parent_ls->l, parent_ls, child_ls, true);
        return;
    }

    line_t *parent_line = child_ls->parent->l;

    muxserver_lstate_t *parent_ls = lineGetState(parent_line, t);

    lineRef(parent_line);
    parent_ls->last_writer = child_l; // update the last writer to the current child

    tunnelPrevDownStreamPayload(t, parent_line, encoded);

    if (lineIsAlive(parent_line))
    {
        parent_ls->last_writer = NULL; // reset the last writer after sending the payload
    }
    lineUnref(parent_line);
}
