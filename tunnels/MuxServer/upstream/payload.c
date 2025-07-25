#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    // muxserver_tstate_t *ts        = tunnelGetState(t);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);
    // wid_t               wid       = lineGetWID(parent_l);

    bufferstreamPush(parent_ls->read_stream, buf);

    while (true)
    {
        mux_frame_t frame        = {0};
        sbuf_t     *frame_buffer = NULL;

        if (bufferstreamLen(parent_ls->read_stream) >= kMuxFrameLength)
        {
            bufferstreamViewBytesAt(parent_ls->read_stream, 0, (uint8_t *) &frame, kMuxFrameLength);

            if ((size_t) frame.length + (size_t) kMuxFrameLength > bufferstreamLen(parent_ls->read_stream))
            {
                // not enough data for a full frame
                break;
            }
            frame_buffer = bufferstreamReadExact(parent_ls->read_stream, frame.length + kMuxFrameLength);
        }
        else
        {
            break; // not enough data for a full frame
        }

        if (frame.flags == kMuxFlagOpen)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            LOGD("MuxServer: UpStreamPayload: Open frame received, cid: %u", frame.cid);

            line_t             *child_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(parent_l));
            muxserver_lstate_t *new_child_ls = lineGetState(child_l, t);
            muxserverLinestateInitialize(new_child_ls, child_l, true);
            muxserverJoinConnection(parent_ls, new_child_ls);
            lineLock(parent_l);
            tunnelNextUpStreamInit(t, child_l);

            if (! lineIsAlive(parent_l))
            {
                LOGD("MuxServer: UpStreamPayload: Parent line is closed when opening line %u", frame.cid);
                lineUnlock(parent_l);
                return;
            }
            lineUnlock(parent_l);

            continue; // Continue to process the next frame
        }

        // Start from the first child in the doubly linked list
        muxserver_lstate_t *child_ls = parent_ls->child_next;
        while (child_ls)
        {
            if (child_ls->connection_id == frame.cid)
            {
                // Found the child line state for this frame
                break;
            }
            muxserver_lstate_t *temp = child_ls->child_next;
            child_ls                 = temp;
        }

        if (! child_ls)
        {
            // No child line state found for this frame, log and skip
            LOGD("MuxServer: UpStreamPayload: No child line state found for cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            continue;
        }

        // Move-to-front optimization: if the found child is not already the first child,
        // move it to the front of the list for faster future access
        if (child_ls != parent_ls->child_next)
        {
            // Remove child_ls from its current position
            if (child_ls->child_prev)
            {
                child_ls->child_prev->child_next = child_ls->child_next;
            }
            if (child_ls->child_next)
            {
                child_ls->child_next->child_prev = child_ls->child_prev;
            }

            // Insert child_ls at the front of the list
            child_ls->child_prev = NULL;
            child_ls->child_next = parent_ls->child_next;
            if (parent_ls->child_next)
            {
                parent_ls->child_next->child_prev = child_ls;
            }
            parent_ls->child_next = child_ls;
        }

        lineLock(parent_l);

        switch (frame.flags)
        {

        case kMuxFlagClose:
            LOGD("MuxServer: UpStreamPayload: Close frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelNextUpStreamFinish(t, child_ls->l);

            break;

        case kMuxFlagFlowPause:
            LOGD("MuxServer: UpStreamPayload: FlowPause frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelNextUpStreamPause(t, child_ls->l);
            break;

        case kMuxFlagFlowResume:
            LOGD("MuxServer: UpStreamPayload: FlowResume frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelNextUpStreamResume(t, child_ls->l);
            break;

        case kMuxFlagData:
            LOGD("MuxServer: UpStreamPayload: Data frame received, cid: %u", frame.cid);
            // remove the frame header from the buffer
            sbufShiftRight(buf, kMuxFrameLength);
            // and write the data to the child line state
            tunnelNextUpStreamPayload(t, child_ls->l, frame_buffer);

            break;

        default:
            LOGD("MuxServer: UpStreamPayload: Unknown frame type received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            break;
        }

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxServer: UpStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }
}
