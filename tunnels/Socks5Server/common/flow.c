#include "internal.h"

#include "loggers/network_logger.h"

bool socks5serverQueueControl(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    socks5server_lstate_t *ls      = lineGetState(l, t);
    buffer_queue_t        *queue   = upstream ? &ls->pending_up : &ls->pending_down;
    const size_t           prefix  = upstream ? bufferstreamGetBufLen(&ls->in_stream) : 0;
    const size_t           length  = sbufGetLength(buf);
    const size_t           entries = upstream ? (size_t) bs_doublequeue_t_size(&ls->in_stream.q) : 0;
    if (UNLIKELY(length > kSocks5ServerMaxPendingBytes || prefix > kSocks5ServerMaxPendingBytes - length ||
                 bufferqueueGetBufLen(queue) > kSocks5ServerMaxPendingBytes - length - prefix ||
                 entries >= kSocks5ServerMaxPendingBuffers ||
                 bufferqueueGetBufCount(queue) >= kSocks5ServerMaxPendingBuffers - entries ||
                 ! bufferqueueTryPushBack(queue, &buf)))
    {
        lineReuseBuffer(l, buf);
        socks5serverCloseControlLineBidirectional(t, l);
        return false;
    }
    return true;
}

bool socks5serverDrainControl(tunnel_t *t, line_t *l)
{
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->control_draining)
        return true;
    ls->control_draining = true;
    if (ls->transport_est_forwarded && ! ls->connect_reply_sent && ! ls->prev_paused)
    {
        sbuf_t *reply = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, NULL);
        if (UNLIKELY(reply == NULL))
        {
            socks5serverCloseControlLineBidirectional(t, l);
            return false;
        }
        ls->phase              = kSocks5ServerPhaseTcpEstablished;
        ls->connect_reply_sent = true;
        if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, reply)))
            return false;
    }
    // The original request tail precedes any input nested in Init or Est.
    while (! ls->input_draining && ! ls->next_initializing && ! ls->next_paused &&
           (! bufferstreamIsEmpty(&ls->in_stream) || bufferqueueGetBufCount(&ls->pending_up)))
    {
        sbuf_t *buf = ! bufferstreamIsEmpty(&ls->in_stream) ? bufferstreamIdealRead(&ls->in_stream)
                                                            : bufferqueuePopFront(&ls->pending_up);
        if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf)))
            return false;
    }
    while (ls->connect_reply_sent && ! ls->prev_paused && bufferqueueGetBufCount(&ls->pending_down))
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_down);
        if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, buf)))
            return false;
    }
    ls->control_draining = false;
    return true;
}

void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    if (ls->transport_est_forwarded)
        return;
    ls->transport_est_forwarded = true;
    if (! lineCallWithRef(l, tunnelPrevDownStreamEst, t))
        return;
    discard socks5serverDrainControl(t, l);
}
