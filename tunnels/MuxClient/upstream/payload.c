#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    // Neighbours may flush final bytes before Finish, even after MUX worker drain.
    if (ts->worker_states[lineGetWID(child_l)].quiescing)
    {
        lineReuseBuffer(child_l, buf);
        return;
    }
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    if (child_ls->close_state != kMuxClientChildCloseOpen)
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

    const bool send_open = ! child_ls->open_frame_submitted;

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

    discard muxclientSendParentOutput(t, child_ls->parent->l, encoded, child_ls, kMuxFlagData);
}
