#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Clears every callback lwIP could still use to reach this line state. Once this
 * has run under the core lock, no in-flight or future lwIP callback can observe
 * `ls`, which is what makes destroying the line state afterwards safe.
 */
struct tcp_pcb *ctpTcpDetachCallbacksLocked(ctp_lstate_t *ls)
{
    struct tcp_pcb *pcb = ls->tcp_pcb;

    if (pcb == NULL)
    {
        return NULL;
    }

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    pcb->connected = NULL;

    /*
     * Both wakeup states go with the callbacks that produced them. The poll is
     * disarmed by the tcp_poll() above; clearing the flag keeps a later flush
     * from believing one is still installed. A queued retry task may still be in
     * flight, but it will find no pcb and do nothing, so the slot it was holding
     * is free.
     */
    ls->write_poll_armed     = false;
    ls->write_retry_queued   = false;
    ls->refused_retry_queued = false;
    ls->tcp_pcb              = NULL;
    return pcb;
}

/*
 * The one TX-only shutdown of a connected flow, and nothing else.
 *
 * It never frees the pcb: every state it accepts moves to FIN_WAIT_1 or
 * LAST_ACK, and the caller still owns the pointer afterwards. That is the whole
 * reason it is separate from the close paths. The helper it replaced answered a
 * refusal with tcp_close(), which both sets TF_RXCLOSED - so lwIP resets the
 * connection on the peer's next legal byte, exactly what a half-close exists to
 * allow - and may free the pcb, so callers could not tell from an err_t whether
 * they still had one.
 *
 * It also cannot be called twice. lwIP changes the state on success and answers
 * ERR_CONN the second time; the closer treats sending the FIN as a one-way
 * transition for the same reason.
 */
err_t ctpTcpSendFinLocked(struct tcp_pcb *pcb)
{
    if (pcb->state != ESTABLISHED && pcb->state != CLOSE_WAIT && pcb->state != SYN_RCVD)
    {
        // Reported rather than worked around: the caller resets instead.
        return ERR_CONN;
    }

    return tcp_shutdown(pcb, 0, 1);
}

void ctpTcpReturnReceiveCreditLocked(ctp_lstate_t *ls, uint32_t amount)
{
    assert(ls->tcp_pcb != NULL);
    assert(amount <= ls->rx_uncredited);

    uint32_t remaining = amount;
    while (remaining > 0)
    {
        const u16_t chunk = (u16_t) min(remaining, (uint32_t) UINT16_MAX);
        tcp_recved(ls->tcp_pcb, chunk);
        remaining -= chunk;
    }
    ls->rx_uncredited -= amount;
}

/*
 * A terminal active-flow transition. The registry is cleared before tcp_abort()
 * can free the pcb, and both operations happen inside the caller's one core-lock
 * section, so Stop can never observe a freed pcb through the registry.
 */
bool ctpTcpAbortFlowLocked(tunnel_t *t, ctp_lstate_t *ls)
{
    struct tcp_pcb *pcb = ctpTcpDetachCallbacksLocked(ls);

    ctpFlowUnregister(t, ls);
    if (pcb == NULL)
    {
        return false;
    }

    tcp_abort(pcb);
    return true;
}

bool ctpTcpOpenFlow(tunnel_t *t, line_t *l, ctp_lstate_t *ls, const ip_addr_t *dest_ip, uint16_t dest_port)
{
    ctp_tstate_t   *ts  = tunnelGetState(t);
    struct tcp_pcb *pcb = NULL;
    bool            ok  = false;

    LOCK_TCPIP_CORE();

    /*
     * Stop may have won the core lock first. Rechecking the gate under the same
     * lock that serializes flow creation makes that cleanup a stable barrier.
     */
    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        goto done;
    }

    ctp_netif_ctx_t *ctx = ctpEnsureNetifLocked(t, lineGetWID(l));
    if (ctx == NULL)
    {
        LOGE("ConnectionToPackets: could not create the virtual netif for worker %d", workerWIDForLog(lineGetWID(l)));
        goto done;
    }

    pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL)
    {
        LOGE("ConnectionToPackets: out of lwIP TCP pcbs, closing this flow");
        goto done;
    }

    ip_addr_t local_ip;
    ipAddrCopyFromIp4(local_ip, ts->source_ip);

    if (tcp_bind_netif(pcb, &ctx->netif) != ERR_OK)
    {
        LOGE("ConnectionToPackets: virtual netif is being removed");
        goto done;
    }

    // Port 0 makes lwIP pick a free ephemeral port now, so the exact inbound
    // tuple is known before the flow is published.
    if (tcp_bind(pcb, &local_ip, 0) != ERR_OK)
    {
        LOGE("ConnectionToPackets: could not bind a local port for the virtual source address");
        goto done;
    }

    ls->tcp_pcb  = pcb;
    ls->flow_key = (ctp_flow_key_t) {
        .remote_addr_network = ip_2_ip4(dest_ip)->addr,
        .local_addr_network  = ip4_addr_get_u32(&ts->source_ip),
        .remote_port         = dest_port,
        .local_port          = pcb->local_port,
        .protocol            = IP_PROTO_TCP,
    };

    if (! ctpFlowRegister(t, ls, pcb, IP_PROTO_TCP))
    {
        ls->tcp_pcb = NULL;
        goto done;
    }

    tcp_arg(pcb, ls);
    tcp_recv(pcb, ctpTcpRecvCallback);
    tcp_sent(pcb, ctpTcpSentCallback);
    tcp_err(pcb, ctpTcpErrorCallback);
    tcp_nagle_disable(pcb);

    if (tcp_connect(pcb, dest_ip, dest_port, ctpTcpConnectedCallback) != ERR_OK)
    {
        LOGE("ConnectionToPackets: lwIP refused the active TCP open");
        ctpFlowUnregister(t, ls);
        discard ctpTcpDetachCallbacksLocked(ls);
        goto done;
    }

    pcb = NULL; // ownership stays with the flow
    ok  = true;

done:
    if (pcb != NULL)
    {
        if (tcp_close(pcb) != ERR_OK)
        {
            tcp_abort(pcb);
        }
    }
    UNLOCK_TCPIP_CORE();
    return ok;
}

/*
 * Hands as much of the pending queue to lwIP as its send window accepts.
 *
 * Nothing is written before the handshake completes, but the queue is still the
 * single ordering authority: a payload that arrives during the connect window is
 * queued exactly like one that arrives while the window is full, and the caller
 * publishes the resulting `write_blocked` state toward prev either way.
 */
ctp_flush_result_t ctpFlushPendingLocked(ctp_lstate_t *ls)
{
    struct tcp_pcb    *pcb       = ls->tcp_pcb;
    bool               wrote_any = false;
    ctp_flush_result_t result    = kCtpFlushProgressed;

    /*
     * Every core-locked write to a pcb funnels through here, so this is where
     * the stopping gate has to be rechecked: drain closes the pcb and clears
     * ls->tcp_pcb under this same lock, and a task that took the lock first
     * would otherwise still be holding the pre-quiesce pointer.
     */
    if (UNLIKELY(ctpTunnelIsStopping(ls->tunnel)))
    {
        pcb = NULL;
    }

    if (pcb != NULL && ls->connected)
    {
        while (bufferqueueGetBufCount(&ls->pending_queue) > 0)
        {
            sbuf_t        *buf       = bufferqueuePopFront(&ls->pending_queue);
            const uint32_t buf_len   = sbufGetLength(buf);
            const uint16_t available = tcp_sndbuf(pcb);

            if (available == 0)
            {
                bufferqueuePushFront(&ls->pending_queue, buf);
                result = kCtpFlushRetryable;
                break;
            }

            const uint16_t write_len = (uint16_t) min((uint32_t) available, buf_len);
            const err_t    written   = tcp_write(pcb, sbufGetMutablePtr(buf), write_len, TCP_WRITE_FLAG_COPY);

            if (written != ERR_OK)
            {
                bufferqueuePushFront(&ls->pending_queue, buf);

                /*
                 * Only ERR_MEM comes back. Anything else - a pcb that has left a
                 * writable state, above all - will come back forever, and
                 * retrying it just keeps the line paused with no way out.
                 */
                result = (written == ERR_MEM) ? kCtpFlushRetryable : kCtpFlushTerminal;
                break;
            }

            wrote_any = true;

            if (write_len == buf_len)
            {
                // TCP_WRITE_FLAG_COPY already handed lwIP its own copy.
                bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(ls->line)), buf);
                continue;
            }

            sbufShiftRight(buf, write_len);
            bufferqueuePushFront(&ls->pending_queue, buf);
            result = kCtpFlushRetryable;
            break;
        }

        if (wrote_any)
        {
            tcp_output(pcb);
        }
    }

    ls->write_blocked = bufferqueueGetBufCount(&ls->pending_queue) > 0;

    /*
     * A queue that could not be emptied has to have something that will come
     * back to it. tcp_sent() only fires when an acknowledgement arrives, and a
     * first write that fails on an idle pcb leaves nothing unacknowledged - so
     * the poll callback is what breaks that tie.
     */
    if (ls->write_blocked && result != kCtpFlushTerminal && pcb != NULL)
    {
        tcp_poll(pcb, ctpTcpPollCallback, kCtpWritePollInterval);
        ls->write_poll_armed = true;
    }
    else if (ls->write_poll_armed && pcb != NULL)
    {
        tcp_poll(pcb, NULL, 0);
        ls->write_poll_armed = false;
    }

    return result;
}

/*
 * Queues one write retry on the owner worker, and only one.
 *
 * Both wakeup sources land here: the 500 ms poll on lwIP's timer thread and a
 * sent callback that arrived on the wrong worker. Neither may flush - they would
 * be touching a buffer pool that belongs to somebody else - so both can do
 * nothing but ask the owner, and an owner that is slow to answer would otherwise
 * collect one message and one line reference per source per half-second.
 *
 * The caller holds the core lock, which is what makes the flag a mutual
 * exclusion between those two threads. A refused required enqueue clears the
 * optimistic flag, detaches the exact producer and publishes the line through
 * the preallocated owner-worker terminal registry; there is no later retry for
 * that flow.
 */
static bool ctpQueueWriteRetryLocked(ctp_lstate_t *ls)
{
    if (ls->write_retry_queued || ! lineIsAlive(ls->line))
    {
        return false;
    }

    ls->write_retry_queued = true;

    if (! lineScheduleTask(ls->line, ctpResumeWriteTask, ls->tunnel))
    {
        ls->write_retry_queued = false;
        return ctpRequiredControlRefusedLocked(ls->tunnel, ls, "TCP write retry");
    }
    return false;
}

/*
 * The retry source for a write that lwIP could not take.
 *
 * It runs on the lwIP timer thread, which may not touch this line's buffer pool,
 * so it never flushes here - it hands the work to the owner worker. `ls` stays
 * valid because every detach path clears this callback under the core lock.
 */
err_t ctpTcpPollCallback(void *arg, struct tcp_pcb *tpcb)
{
    ctp_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kCtpLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    if (! ls->connected || ! ls->write_blocked)
    {
        tcp_poll(tpcb, NULL, 0);
        ls->write_poll_armed = false;
        return ERR_OK;
    }

    return ctpQueueWriteRetryLocked(ls) ? ERR_ABRT : ERR_OK;
}

err_t ctpTcpConnectedCallback(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    ctp_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kCtpLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    if (UNLIKELY(err != ERR_OK))
    {
        // lwIP only reports a failed connect through tcp_err(), so this is a
        // defensive branch rather than the normal refusal path.
        LOGD("ConnectionToPackets: tcp connect reported error %d", (int) err);

        // Released here rather than on the owner worker, so the close path finds
        // no pcb and cannot hand anything still queued to a drain: this
        // connection never came up and never will.
        discard ctpTcpAbortFlowLocked(ls->tunnel, ls);

        if (lineIsAlive(ls->line))
        {
            if (! lineScheduleTask(ls->line, ctpCloseLineTask, ls->tunnel))
            {
                discard ctpRequiredControlRefusedLocked(ls->tunnel, ls, "TCP connect-error close");
            }
        }
        return ERR_ABRT;
    }

    assert(lineIsOnCurrentEventWorker(ls->line));

    if (lineIsAlive(ls->line))
    {
        /* Win the deadline race in this callback, before any queued task runs. */
        ls->connected = true;
        ctpCancelConnectDeadline(ls);
        if (! lineScheduleTask(ls->line, ctpEstablishedTask, ls->tunnel))
        {
            if (ctpRequiredControlRefusedLocked(ls->tunnel, ls, "TCP Established"))
            {
                return ERR_ABRT;
            }
        }
    }

    return ERR_OK;
}

err_t ctpTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    ctp_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kCtpLineKindTcp || ls->tcp_pcb != tpcb)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    if (err != ERR_OK)
    {
        // A terminal receive error. Close from this side too and let the owner
        // worker report it toward prev.
        if (p != NULL)
        {
            pbuf_free(p);
        }

        /* A receive error is terminal and resets the flow. */
        const bool aborted = ctpDetachFlowLocked(t, ls, false);

        if (lineIsAlive(l))
        {
            if (! lineScheduleTask(l, ctpCloseLineTask, t))
            {
                discard ctpRequiredControlRefusedLocked(t, ls, "TCP receive-error close");
            }
        }
        return aborted ? ERR_ABRT : ERR_OK;
    }

    if (p == NULL)
    {
        /*
         * A clean remote FIN is only a receive-side half-close: the peer may
         * keep reading. Move every accepted outbound byte and the PCB to the
         * graceful closer synchronously, while this callback still owns the
         * core lock. The owner close task may be refused or delayed, and it is
         * only responsible for the borrowed line and the report toward prev;
         * it cannot be allowed to decide whether the peer gets bytes we have
         * already accepted.
         */
        const bool aborted = ctpDetachFlowLocked(t, ls, true);

        if (lineIsAlive(l) && ! lineScheduleTask(l, ctpCloseLineTask, t))
        {
            discard ctpRequiredControlRefusedLocked(t, ls, "TCP peer-FIN close");
        }
        return aborted ? ERR_ABRT : ERR_OK;
    }

    const wid_t owner_wid = lineGetWID(l);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        /*
         * The read buffer would have to come from the owner's pool, which this
         * thread may not touch. Injection is always posted to the owner, so this
         * only happens if lwIP replayed refused data from its timer thread.
         */
        if (! ls->refused_retry_queued)
        {
            ls->refused_retry_queued = true;
            if (! lineIsAlive(l) || ! lineScheduleTask(l, ctpRefusedDataRetryTask, t))
            {
                ls->refused_retry_queued = false;
                if (ctpRequiredControlRefusedLocked(t, ls, "refused TCP data replay"))
                {
                    return ERR_ABRT;
                }
            }
        }
        return ERR_MEM;
    }

    const uint32_t received = p->tot_len;
    buffer_pool_t *pool     = lineGetBufferPool(l);
    sbuf_t        *buf      = bufferpoolGetBestFit(pool, received, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, received);
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), received, 0);

    if (UNLIKELY(received > UINT32_MAX - ls->rx_uncredited))
    {
        lineReuseBuffer(l, buf);
        pbuf_free(p);
        const bool aborted = ctpTcpAbortFlowLocked(t, ls);
        if (lineIsAlive(l))
        {
            if (! lineScheduleTask(l, ctpCloseLineTask, t))
            {
                discard ctpRequiredControlRefusedLocked(t, ls, "TCP receive-overflow close");
            }
        }
        return aborted ? ERR_ABRT : ERR_OK;
    }
    /*
     * Delivery has to leave the core lock first, so it is handed to the owner
     * worker as a line task instead of calling prev from inside lwIP.
     */
    if (! lineIsAlive(l))
    {
        /* The owner-pool pointer was captured while the line was alive. */
        bufferpoolReuseBuffer(pool, buf);
        return ERR_MEM;
    }

    if (! lineScheduleTaskWithBuf(l, ctpDeliverPayloadTask, t, buf))
    {
        /* Scheduler cleanup owns the copied sbuf; lwIP retains and replays p. */
        return ERR_MEM;
    }

    ls->rx_uncredited += received;
    pbuf_free(p);
    return ERR_OK;
}

err_t ctpTcpSentCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    discard len;

    ctp_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kCtpLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    if (! ls->write_blocked)
    {
        return ERR_OK;
    }

    /*
     * tcp_sent only fires from ACK processing in tcp_input(), which for this pcb
     * always runs on the injection worker - the owner. The guard keeps a future
     * lwIP path from letting the flush touch a foreign worker's buffer pool.
     */
    if (UNLIKELY(! currentThreadIsEventWorkerWID(lineGetWID(ls->line))))
    {
        return ctpQueueWriteRetryLocked(ls) ? ERR_ABRT : ERR_OK;
    }

    const ctp_flush_result_t flushed = ctpFlushPendingLocked(ls);

    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        /*
         * Nothing will ever take these bytes. Finish with the pcb here, inside
         * the one core-locked section that already owns it, rather than leaving
         * it registered for the owner task to rediscover: that route would let
         * the close path adopt a closer for a pcb whose writes are already
         * failing, only to abort it a moment later.
         *
         * tcp_abort() frees the pcb, so lwIP has to be told this callback did
         * that - hence ERR_ABRT rather than ERR_OK. Only the report toward prev
         * is left for the owner, and it needs no pcb.
         */
        const bool aborted = ctpTcpAbortFlowLocked(ls->tunnel, ls);

        if (lineIsAlive(ls->line))
        {
            if (! lineScheduleTask(ls->line, ctpCloseLineTask, ls->tunnel))
            {
                discard ctpRequiredControlRefusedLocked(ls->tunnel, ls, "terminal-write close");
            }
        }
        return aborted ? ERR_ABRT : ERR_OK;
    }

    if (! ls->write_blocked && ls->write_paused && lineIsAlive(ls->line))
    {
        // Still inside lwIP with the core lock held, so the Resume toward prev
        // has to be scheduled rather than called here.
        if (ctpQueueWriteRetryLocked(ls))
        {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

void ctpTcpErrorCallback(void *arg, err_t err)
{
    ctp_lstate_t *ls = arg;

    if (ls == NULL)
    {
        return;
    }

    LOGD("ConnectionToPackets: tcp connection error %d", (int) err);

    // lwIP already freed the pcb before invoking this callback.
    ls->tcp_pcb = NULL;
    ctpFlowUnregister(ls->tunnel, ls);

    if (lineIsAlive(ls->line))
    {
        if (! lineScheduleTask(ls->line, ctpCloseLineTask, ls->tunnel))
        {
            discard ctpRequiredControlRefusedLocked(ls->tunnel, ls, "TCP error close");
        }
    }
}
