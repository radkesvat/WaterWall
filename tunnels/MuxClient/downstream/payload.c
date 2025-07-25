#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    wid_t               wid       = lineGetWID(parent_l);

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


        // Start from the first child in the doubly linked list
        muxclient_lstate_t *child_ls = parent_ls->child_next;
        while (child_ls)
        {
            if (child_ls->connection_id == frame.cid)
            {
                // Found the child line state for this frame
                break;
            }
            muxclient_lstate_t *temp = child_ls->child_next;
            child_ls                 = temp;
        }

        if (! child_ls)
        {
            // No child line state found for this frame, log and skip
            LOGD("MuxClient: DownStreamPayload: No child line state found for cid: %u", frame.cid);
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
        case kMuxFlagOpen:
            LOGE("MuxClient: DownStreamPayload: Open frame received, cid: %u, but no Open flag should be sent to "
                 "MuxClient node",
                 frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);

            break;

        case kMuxFlagClose:
            LOGD("MuxClient: DownStreamPayload: Close frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelPrevDownStreamFinish(t, child_ls->l);
            if (! lineIsAlive(parent_l))
            {
                lineUnlock(parent_l);
                return;
            }
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
                return;
            }
            break;

        case kMuxFlagFlowPause:
            LOGD("MuxClient: DownStreamPayload: FlowPause frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelPrevDownStreamPause(t, child_ls->l);
            break;

        case kMuxFlagFlowResume:
            LOGD("MuxClient: DownStreamPayload: FlowResume frame received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            tunnelPrevDownStreamResume(t, child_ls->l);
            break;

        case kMuxFlagData:
            LOGD("MuxClient: DownStreamPayload: Data frame received, cid: %u", frame.cid);
            // remove the frame header from the buffer
            sbufShiftRight(buf, kMuxFrameLength);
            // and write the data to the child line state
            tunnelPrevDownStreamPayload(t, child_ls->l, frame_buffer);

            break;

        default:
            LOGD("MuxClient: DownStreamPayload: Unknown frame type received, cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            break;
        }

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxClient: DownStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }
}
