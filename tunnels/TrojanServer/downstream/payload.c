#include "structure.h"

/* Next -> client: UDP backend replies are encoded into the client's owned reply
 * FIFO; forwardQueuedReplies() in common/flow.c waits for backend Est and client
 * permission. Fallback transfers ownership to trojanserverPumpFallbackReplies()
 * in common/fallback.c, which needs no Est. TCP transfers buf directly when ready,
 * otherwise pending_down owns it until forwardQueuedReplies() can deliver it. */
void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        line_t                *client_l = ls->client_line;
        trojanserver_lstate_t *client   = lineGetState(client_l, t);
        if (UNLIKELY(client->phase == kTrojanServerPhaseClosing))
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (UNLIKELY(! trojanserverWrapUdpPayload(l, &buf)))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
        if (UNLIKELY(sbufGetLength(buf) > kTrojanServerMaxPendingBytes - client->reply_bytes ||
                     client->reply_count >= kTrojanServerMaxQueuedBuffers))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, client_l);
            return;
        }
        trojanserver_reply_t *reply = memoryAllocate(sizeof(*reply));
        if (UNLIKELY(reply == NULL))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, client_l);
            return;
        }
        *reply = (trojanserver_reply_t) {.buf = buf, .waiter = ls->next_established ? NULL : l};
        if (client->reply_tail != NULL)
            client->reply_tail->next = reply;
        else
            client->reply_head = reply;
        client->reply_tail = reply;
        client->reply_bytes += sbufGetLength(buf);
        ++client->reply_count;
        trojanserverPump(t, client_l);
        return;
    }
    if (ls->branch == kTrojanServerBranchFallback)
    {
        trojanserverPumpFallbackReplies(t, l, buf);
        return;
    }
    if (ls->phase == kTrojanServerPhaseWaitInitial || trojanserverIsUdp(ls))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    buffer_queue_t *queue = &ls->pending_down;
    if (! ls->pumping && ! ls->branch_initializing && ! ls->prev_paused && ls->prev_est_sent &&
        bufferqueueGetBufCount(queue) == 0)
    {
        lineRef(l);
        ls->pumping = true;
        tunnelPrevDownStreamPayload(t, l, buf);
        if (LIKELY(lineIsAlive(l)))
        {
            ls->pumping = false;
            trojanserverPump(t, l);
        }
        lineUnref(l);
        return;
    }
    if (UNLIKELY(! trojanserverQueuePayload(queue, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    trojanserverPump(t, l);
}
