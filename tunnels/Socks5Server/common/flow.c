#include "internal.h"

#include "loggers/network_logger.h"

bool socks5serverQueueControl(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    socks5server_lstate_t *ls      = lineGetState(l, t);
    buffer_queue_t        *queue   = upstream ? &ls->pending_up : &ls->pending_down;
    const size_t           prefix  = upstream ? bufferstreamGetBufLen(&ls->in_stream) : 0;
    const size_t           length  = sbufGetLength(buf);
    const size_t           entries = upstream ? bufferstreamGetEntryCount(&ls->in_stream) : 0;
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
    // An Est callback may have completed setup and bypassed us before returning.
    if (! tunnelIsActiveForLine(t, l))
        return true;
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->control_draining)
        return true;
    ls->control_draining = true;
    if (ls->transport_est_forwarded && ! ls->connect_reply_sent)
    {
        sbuf_t *reply          = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, NULL);
        ls->phase              = kSocks5ServerPhaseTcpEstablished;
        ls->connect_reply_sent = true;
        if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, reply)))
            return false;
    }
    // Either direction can admit work for the other while this drain owns ordering.
    do
    {
        // The original request tail precedes any input nested in Init or Est.
        while (! ls->input_draining && ! ls->next_initializing &&
               (! bufferstreamIsEmpty(&ls->in_stream) || bufferqueueGetBufCount(&ls->pending_up)))
        {
            sbuf_t *buf = ! bufferstreamIsEmpty(&ls->in_stream) ? bufferstreamIdealRead(&ls->in_stream)
                                                                : bufferqueuePopFront(&ls->pending_up);
            if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf)))
                return false;
        }
        while (ls->connect_reply_sent && bufferqueueGetBufCount(&ls->pending_down))
        {
            sbuf_t *buf = bufferqueuePopFront(&ls->pending_down);
            if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, buf)))
                return false;
        }
    } while (! ls->input_draining && ! ls->next_initializing &&
             (! bufferstreamIsEmpty(&ls->in_stream) || bufferqueueGetBufCount(&ls->pending_up)));
    ls->control_draining = false;
    if (ls->kind == kSocks5ServerLineKindControlTcp && ls->phase == kSocks5ServerPhaseTcpEstablished &&
        ! ls->input_draining && ! ls->next_initializing && ! ls->pending_read_pause)
    {
        assert(ls->next_initialized && ls->connect_reply_sent);
        assert(bufferstreamIsEmpty(&ls->in_stream) && bufferqueueGetBufCount(&ls->pending_up) == 0 &&
               bufferqueueGetBufCount(&ls->pending_down) == 0);
        socks5serverLinestateDestroy(ls);
        tunnelBypassLine(t, l);
    }
    return true;
}

void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    ls->transport_est_forwarded = true;
    if (! lineCallWithRef(l, tunnelPrevDownStreamEst, t))
        return;
    discard socks5serverDrainControl(t, l);
}
