#include "structure.h"

#include "loggers/network_logger.h"

/*
 * One clock for every deadline this node compares.
 *
 * wloopNowMS() only exists on an event worker's thread, while tombstone,
 * fragment and drain lifetimes are also observed from lwIP's timer thread. The
 * high-resolution source is monotonic and callable from either context, so clock
 * corrections cannot extend or prematurely expire these internal lifetimes.
 */
uint64_t ctpNowMs(void)
{
    return (uint64_t) (getHRTimeUs() / 1000ULL);
}

bool ctpTunnelIsStopping(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    return atomicLoadRelaxed(&ts->stopping);
}

static bool ctpGateEnter(tunnel_t *t, quiescence_gate_t *gate)
{
    if (UNLIKELY(ctpTunnelIsStopping(t) || ! quiescenceGateEnter(gate)))
    {
        return false;
    }
    if (UNLIKELY(ctpTunnelIsStopping(t)))
    {
        quiescenceGateLeave(gate);
        return false;
    }
    return true;
}

bool ctpPrevGateEnter(tunnel_t *t)
{
    return ctpGateEnter(t, &((ctp_tstate_t *) tunnelGetState(t))->prev_gate);
}

void ctpPrevGateLeave(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    quiescenceGateLeave(&ts->prev_gate);
}

bool ctpNextGateEnter(tunnel_t *t)
{
    return ctpGateEnter(t, &((ctp_tstate_t *) tunnelGetState(t))->next_gate);
}

bool ctpPacketIngressGateEnter(tunnel_t *t)
{
    return ctpGateEnter(t, &((ctp_tstate_t *) tunnelGetState(t))->packet_ingress_gate);
}

void ctpPacketIngressGateLeave(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    quiescenceGateLeave(&ts->packet_ingress_gate);
}

void ctpNextGateLeave(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    quiescenceGateLeave(&ts->next_gate);
}

static void ctpTerminalEnqueue(tunnel_t *t, ctp_lstate_t *ls)
{
    ctp_tstate_t *ts  = tunnelGetState(t);
    const wid_t   wid = lineGetWID(ls->line);

    rwlockWriteLock(&ts->flows_lock);
    if (! ls->terminal_pending)
    {
        lineLock(ls->line);
        line_t *head      = ts->terminal_lines[wid];
        ls->terminal_prev = NULL;
        ls->terminal_next = head;
        if (head != NULL)
        {
            ((ctp_lstate_t *) lineGetState(head, t))->terminal_prev = ls->line;
        }
        ts->terminal_lines[wid] = ls->line;
        ls->terminal_pending    = true;
    }
    rwlockWriteUnlock(&ts->flows_lock);
}

void ctpTerminalCancel(ctp_lstate_t *ls)
{
    if (! ls->terminal_pending)
    {
        return;
    }

    tunnel_t     *t                 = ls->tunnel;
    ctp_tstate_t *ts                = tunnelGetState(t);
    const wid_t   wid               = lineGetWID(ls->line);
    bool          release_reference = false;

    rwlockWriteLock(&ts->flows_lock);
    if (ls->terminal_pending)
    {
        if (ls->terminal_prev != NULL)
        {
            ((ctp_lstate_t *) lineGetState(ls->terminal_prev, t))->terminal_next = ls->terminal_next;
        }
        else
        {
            assert(ts->terminal_lines[wid] == ls->line);
            ts->terminal_lines[wid] = ls->terminal_next;
        }
        if (ls->terminal_next != NULL)
        {
            ((ctp_lstate_t *) lineGetState(ls->terminal_next, t))->terminal_prev = ls->terminal_prev;
        }
        ls->terminal_prev    = NULL;
        ls->terminal_next    = NULL;
        ls->terminal_pending = false;
        release_reference    = true;
    }
    rwlockWriteUnlock(&ts->flows_lock);

    if (release_reference)
    {
        lineUnlock(ls->line);
    }
}

bool ctpRequiredControlRefusedLocked(tunnel_t *t, ctp_lstate_t *ls, const char *operation)
{
    /* The caller already owns LOCK_TCPIP_CORE(). Disable the exact producer
     * before publishing the owner-worker terminal handoff. */
    const bool aborted = ctpDetachFlowLocked(t, ls, false);
    ctpTerminalEnqueue(t, ls);

    LOGE("ConnectionToPackets: required owner control '%s' was refused; flow detached", operation);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
    return aborted;
}

void ctpDrainTerminalLinesOnCurrentWorker(tunnel_t *t, wid_t wid)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    assert(currentThreadIsEventWorkerWID(wid));
    if (ts->terminal_lines == NULL || wid >= ts->netifs_count)
    {
        return;
    }

    for (;;)
    {
        rwlockWriteLock(&ts->flows_lock);
        line_t *line = ts->terminal_lines[wid];
        if (line != NULL)
        {
            ctp_lstate_t *ls        = lineGetState(line, t);
            line_t       *next      = ls->terminal_next;
            ts->terminal_lines[wid] = next;
            if (next != NULL)
            {
                ((ctp_lstate_t *) lineGetState(next, t))->terminal_prev = NULL;
            }
            ls->terminal_prev    = NULL;
            ls->terminal_next    = NULL;
            ls->terminal_pending = false;
        }
        rwlockWriteUnlock(&ts->flows_lock);

        if (line == NULL)
        {
            return;
        }

        if (lineIsAlive(line))
        {
            ctpCloseLineTowardPrevWithoutDrain(t, line);
        }
        /* Release the terminal registry's preallocated handoff reference. */
        lineUnlock(line);
    }
}

bool ctpLineIsPacketLine(tunnel_t *t, line_t *l)
{
    return tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
}

// ---------------------------------------------------------------------------
// Destination selection
// ---------------------------------------------------------------------------

static bool ctpProtocolFromContext(const address_context_t *ctx, uint8_t *out_protocol)
{
    switch (addresscontextClassifyTransport(ctx))
    {
    case kAddressContextTransportTcp:
        *out_protocol = IP_PROTO_TCP;
        return true;
    case kAddressContextTransportUdp:
        *out_protocol = IP_PROTO_UDP;
        return true;
    default:
        return false;
    }
}

static void ctpLogUnsupportedContext(const char *label, const address_context_t *ctx)
{
    LOGE("ConnectionToPackets: line has unsupported or ambiguous %s protocol flags "
         "(tcp=%u, udp=%u, icmp=%u, packet=%u)",
         label,
         (unsigned int) ctx->proto_tcp,
         (unsigned int) ctx->proto_udp,
         (unsigned int) ctx->proto_icmp,
         (unsigned int) ctx->proto_packet);
}

/*
 * Deliberately identical to TcpUdpConnector's rule so the two nodes accept the
 * same lines: an exact destination protocol wins, otherwise an exact source
 * protocol is used, and anything missing or ambiguous rejects the line.
 */
bool ctpSelectProtocol(tunnel_t *t, line_t *l, uint8_t *out_protocol)
{
    discard t;

    const address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    const address_context_t *src_ctx  = lineGetSourceAddressContext(l);

    if (addresscontextClassifyTransport(dest_ctx) != kAddressContextTransportNone)
    {
        if (ctpProtocolFromContext(dest_ctx, out_protocol))
        {
            return true;
        }

        ctpLogUnsupportedContext("destination", dest_ctx);
        return false;
    }

    if (ctpProtocolFromContext(src_ctx, out_protocol))
    {
        return true;
    }

    if (addresscontextClassifyTransport(src_ctx) != kAddressContextTransportNone)
    {
        ctpLogUnsupportedContext("source", src_ctx);
    }
    else
    {
        LOGE("ConnectionToPackets: line has no TCP/UDP protocol flags in destination or source context");
    }

    return false;
}

bool ctpDomainResolverPrepare(tunnel_t *resolver, tunnel_t *owner, line_t *l, domainresolver_direction_t direction,
                              void *user_lstate)
{
    discard resolver;
    discard direction;

    ctp_tstate_t                 *ts       = tunnelGetState(owner);
    ctp_domain_resolver_lstate_t *ls       = user_lstate;
    address_context_t            *dest_ctx = lineGetDestinationAddressContext(l);
    uint8_t                       protocol = 0;

    if (! ctpSelectProtocol(owner, l, &protocol))
    {
        return false;
    }

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("ConnectionToPackets: destination port is not initialized");
        return false;
    }

    ls->protocol = protocol;

    // Selecting here rather than in Init means DNS already runs with the right
    // protocol and strategy, and Init only has to consume the result.
    addresscontextSetOnlyProtocol(dest_ctx, protocol);
    addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
    return true;
}

// ---------------------------------------------------------------------------
// Flow teardown
// ---------------------------------------------------------------------------

bool ctpDetachFlowLocked(tunnel_t *t, ctp_lstate_t *ls, bool graceful)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ts->lwip_resources_destroyed))
    {
        /*
         * Stop detached every pcb and cleared the registry under this same lock,
         * so the retained pointers are stale by construction. Only the local
         * bookkeeping is cleared here; touching lwIP would be a use-after-free.
         */
        ls->tcp_pcb         = NULL;
        ls->flow_registered = false;
        ls->generation      = 0;
        return false;
    }

    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        /* Stop was published but has not swept the registry yet. Detach for real. */
        graceful = false;
    }

    if (ls->kind == kCtpLineKindUdp)
    {
        struct udp_pcb *pcb = ctpUdpDetachCallbacksLocked(ls);

        if (pcb != NULL)
        {
            udp_remove(pcb);
        }
        // A datagram flow has nothing left to exchange, so no tombstone is kept.
        ctpFlowRetire(t, ls, false);
        return false;
    }

    if (! graceful)
    {
        return ctpTcpAbortFlowLocked(t, ls);
    }

    // Bytes the application already handed over are still owed to the peer.
    discard ctpFlushPendingLocked(ls);

    /*
     * What the send window would not take stays in the queue, and the line is
     * about to be destroyed. tcp_close() preserves only what lwIP already copied,
     * so anything still queued moves to an instance-owned drain. Refusing that
     * transfer must reset the flow: a clean FIN after dropping an accepted suffix
     * would falsely report a successful shorter stream.
     */
    bool                               drain_aborted = false;
    const ctp_tcp_drain_adopt_result_t adopted       = ctpTcpDrainAdoptLocked(t, ls, &drain_aborted);

    if (adopted == kCtpTcpDrainAdopted)
    {
        return drain_aborted;
    }
    if (adopted == kCtpTcpDrainFailed)
    {
        return ctpTcpAbortFlowLocked(t, ls);
    }

    struct tcp_pcb *pcb = ctpTcpDetachCallbacksLocked(ls);

    if (pcb == NULL)
    {
        ctpFlowRetire(t, ls, false);
        return false;
    }

    /*
     * Adoption only declines for a flow whose handshake never completed and that
     * has nothing queued; every other outcome, including a full closer table, is
     * a failure the branch above already turned into a reset. There is
     * deliberately no untracked-shutdown fallback: a half-closed pcb nothing owns
     * is one lwIP will never reap.
     *
     * tcp_close() is exact for what is left. Nothing was ever received on a
     * connection that never came up, so the reset rule in tcp_close_shutdown()
     * cannot fire, and SYN_SENT is freed on the spot rather than lingering.
     *
     * The guard is not only an assertion because the assertion is compiled out
     * of a release build, and being wrong about it here means calling
     * tcp_close() on an established pcb that still owes receive credit - which
     * resets the flow and discards unacknowledged bytes, the exact outcome this
     * whole close path was rebuilt to avoid. A reset that is chosen is better
     * than one that is stumbled into.
     */
    assert(! ls->connected);

    if (UNLIKELY(ls->connected))
    {
        ctpFlowUnregister(t, ls);
        tcp_abort(pcb);
        return true;
    }

    if (tcp_close(pcb) != ERR_OK)
    {
        /* A refused close leaves pcb valid; unregister before aborting it. */
        ctpFlowUnregister(t, ls);
        tcp_abort(pcb);
        return true;
    }

    // No exchange ever happened, so there is nothing for a tombstone to route.
    ctpFlowRetire(t, ls, false);
    return false;
}

/*
 * A network-originated close: reset, refusal, timeout, remote FIN, or a fatal
 * lwIP error. This node borrows the line, so it destroys only its own state and
 * reports the close toward prev, which owns the line and destroys it.
 */
static void ctpCloseLineTowardPrevInternal(tunnel_t *t, line_t *l, bool graceful)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);

    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL)
    {
        // Another close path already ran for this line.
        lineUnlock(l);
        return;
    }

    const bool callback_admitted = ctpPrevGateEnter(t);

    LOCK_TCPIP_CORE();
    discard ctpDetachFlowLocked(t, ls, graceful);
    UNLOCK_TCPIP_CORE();

    /*
     * Reaching here with live state is itself the proof that prev has not
     * finished this line: its Finish handler destroys this state, and the guard
     * above turns any later close path into a no-op. So no directional-close
     * flag is needed to know the report is still allowed.
     */
    ctpLinestateDestroy(ls);
    if (callback_admitted)
    {
        tunnelPrevDownStreamFinish(t, l);
        ctpPrevGateLeave(t);
    }

    lineUnlock(l);
}

void ctpCloseLineTowardPrev(tunnel_t *t, line_t *l)
{
    ctpCloseLineTowardPrevInternal(t, l, true);
}

/*
 * An admission failure, not an application close. The graceful path flushes the
 * queue and then moves whatever lwIP would not take into an instance-owned
 * closer, which has its own 16 MiB budget - so draining rejected input would let
 * bytes that failed the per-flow limit reach the peer anyway, and would make the
 * limit bound nothing. Reset instead, and report the close to the owning
 * previous side exactly as any other network-originated close does.
 */
void ctpCloseLineTowardPrevWithoutDrain(tunnel_t *t, line_t *l)
{
    ctpCloseLineTowardPrevInternal(t, l, false);
}

void ctpCloseLineTask(tunnel_t *t, line_t *l)
{
    ctpCloseLineTowardPrev(t, l);
}

/*
 * The deadline fired.
 *
 * A one-shot wtimer is already removed from the loop by the time its callback
 * runs, so the handle is cleared first and never deleted here. Clearing it is
 * also the single ownership transition the cancel path relies on: once it is NULL,
 * ctpCancelConnectDeadline() knows the reference below is no longer its to
 * release.
 */
static void ctpConnectDeadlineTimerCallback(wtimer_t *timer)
{
    ctp_lstate_t *ls = weventGetUserdata(timer);

    if (ls == NULL)
    {
        // Cancelled; the canceller already released the line reference.
        return;
    }

    line_t   *l = ls->line;
    tunnel_t *t = ls->tunnel;

    ls->connect_timer = NULL;

    // Not gated on stopping: this is a close path, and prev still owns a
    // borrowed line it needs to be told about.
    if (t != NULL && ! ls->connected && lineIsAlive(l))
    {
        LOGD("ConnectionToPackets: active TCP open timed out before the handshake completed");

        /*
         * The pcb goes first, and it is aborted rather than closed. A handshake
         * that never completed has no peer to deliver to, so whatever is still
         * queued must not be handed to a drain: it would sit there writing into
         * a connection that is not coming up until its own deadline expired.
         */
        LOCK_TCPIP_CORE();
        if (! ctpTunnelIsStopping(t))
        {
            discard ctpTcpAbortFlowLocked(t, ls);
        }
        UNLOCK_TCPIP_CORE();

        ctpCloseLineTowardPrev(t, l);
    }

    lineUnlock(l);
}

bool ctpArmConnectDeadline(tunnel_t *t, line_t *l, ctp_lstate_t *ls)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    assert(ls->connect_timer == NULL);

    ls->connect_timer =
        wtimerAdd(getCurrentEventWorkerLoop(), ctpConnectDeadlineTimerCallback, ts->connect_timeout_ms, 1);

    if (UNLIKELY(ls->connect_timer == NULL))
    {
        return false;
    }

    weventSetUserData(ls->connect_timer, ls);

    // The timer's own reference, released exactly once - by its callback, or by
    // ctpCancelConnectDeadline().
    lineLock(l);
    return true;
}

void ctpCancelConnectDeadline(ctp_lstate_t *ls)
{
    if (ls->connect_timer == NULL)
    {
        return;
    }

    // Clearing the userdata is what makes an already-dispatched callback a
    // no-op; deleting the handle is what stops one that has not been.
    weventSetUserData(ls->connect_timer, NULL);
    wtimerDelete(ls->connect_timer);
    ls->connect_timer = NULL;

    lineUnlock(ls->line);
}

// ---------------------------------------------------------------------------
// Owner-worker delivery
// ---------------------------------------------------------------------------

void ctpDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ctp_lstate_t *ls = lineGetState(l, t);

    /*
     * Workers keep draining their queues after onStop() has run, so a task
     * queued before the stop can still arrive here. Neighbors on both sides may
     * already have stopped by then, and calling into one of them is a
     * composability violation even when the particular neighbor happens to
     * tolerate it. Close paths stay live below - a borrowed line still has to be
     * releasable by its owner - but data and lifecycle events do not.
     */
    if (ls->tunnel == NULL || ctpTunnelIsStopping(t))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const bool     is_tcp   = (ls->kind == (uint8_t) kCtpLineKindTcp);
    const uint32_t received = sbufGetLength(buf);

    if (ls->read_paused && ! is_tcp)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! ctpPrevGateEnter(t))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const bool alive = withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
    ctpPrevGateLeave(t);
    if (! alive)
    {
        return;
    }

    if (! is_tcp)
    {
        return;
    }

    // prev may have paused re-entrantly, or closed the line and taken this state
    // with it, so the receive credit is re-read rather than remembered.
    ls = lineGetState(l, t);

    if (ls->tunnel == NULL)
    {
        return;
    }

    LOCK_TCPIP_CORE();
    // Stop clears this pointer under the same lock, so rechecking here is what
    // keeps a task that raced it from crediting a released pcb.
    if (ls->tcp_pcb != NULL && ! ctpTunnelIsStopping(t))
    {
        if (ls->read_paused)
        {
            assert(received <= UINT32_MAX - ls->read_paused_len);
            ls->read_paused_len += received;
        }
        else
        {
            ctpTcpReturnReceiveCreditLocked(ls, received);
        }
    }
    UNLOCK_TCPIP_CORE();
}

void ctpEstablishedTask(tunnel_t *t, line_t *l)
{
    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL || ls->est_sent || ! ls->connected || ctpTunnelIsStopping(t))
    {
        return;
    }

    ls->est_sent = true;

    LOCK_TCPIP_CORE();
    const ctp_flush_result_t flushed = ctpFlushPendingLocked(ls);
    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        /*
         * Released here rather than left for the close path below. That path
         * would move the unwritable queue into a closer, which would attempt the
         * same write, fail the same way and abort - the same reset, reached
         * through an allocation and a detour.
         */
        discard ctpTcpAbortFlowLocked(t, ls);
    }
    UNLOCK_TCPIP_CORE();

    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        ctpCloseLineTowardPrev(t, l);
        return;
    }

    /*
     * Rechecked after the lock. Waiting for the core lock is unbounded - lwIP's
     * timer thread holds it for whole timer sweeps - so Stop can have run and
     * returned in that window, and prev's own onStop() with it. The gate is not a
     * strict quiescence barrier, but a callback emitted after a neighbour has
     * stopped is a composability violation whether or not that neighbour happens
     * to tolerate it.
     */
    if (ctpTunnelIsStopping(t))
    {
        return;
    }

    if (! ctpPrevGateEnter(t))
    {
        return;
    }
    const bool alive = withLineLocked(l, tunnelPrevDownStreamEst, t);
    ctpPrevGateLeave(t);
    if (! alive)
    {
        return;
    }

    ctpApplyWriteBackpressure(t, l);
}

void ctpResumeWriteTask(tunnel_t *t, line_t *l)
{
    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL)
    {
        return;
    }

    /*
     * This task *is* the queued retry, so the slot it was holding is free again
     * the moment it starts. Clearing it before the flush - rather than after -
     * means a poll that fires while this is running can queue the next one, which
     * is the behaviour a single blocked write needs; clearing it afterwards would
     * drop that wakeup and stall the flow for another half-second at best.
     *
     * Cleared even on the stopping path below: nothing else would.
     */
    LOCK_TCPIP_CORE();
    ls->write_retry_queued = false;
    UNLOCK_TCPIP_CORE();

    if (ctpTunnelIsStopping(t))
    {
        return;
    }

    LOCK_TCPIP_CORE();
    const ctp_flush_result_t flushed = ctpFlushPendingLocked(ls);
    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        /*
         * Released here rather than left for the close path below. That path
         * would move the unwritable queue into a closer, which would attempt the
         * same write, fail the same way and abort - the same reset, reached
         * through an allocation and a detour.
         */
        discard ctpTcpAbortFlowLocked(t, ls);
    }
    UNLOCK_TCPIP_CORE();

    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        /* Nothing will ever take these bytes; report the close toward prev once. */
        ctpCloseLineTowardPrev(t, l);
        return;
    }

    ctpApplyWriteBackpressure(t, l);
}

void ctpRefusedDataRetryTask(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    ctp_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel == NULL)
    {
        return;
    }

    LOCK_TCPIP_CORE();
    ls->refused_retry_queued = false;
    if (ls->tcp_pcb != NULL && ! ctpTunnelIsStopping(t))
    {
        discard tcp_process_refused_data(ls->tcp_pcb);
    }
    UNLOCK_TCPIP_CORE();
}

/*
 * Publishes the current send-window state toward prev. The caller must treat the
 * line as possibly destroyed afterwards: both branches call into prev.
 */
void ctpApplyWriteBackpressure(tunnel_t *t, line_t *l)
{
    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL || ctpTunnelIsStopping(t))
    {
        return;
    }

    if (ls->write_blocked && ! ls->write_paused)
    {
        ls->write_paused = true;
        if (ctpPrevGateEnter(t))
        {
            discard withLineLocked(l, tunnelPrevDownStreamPause, t);
            ctpPrevGateLeave(t);
        }
        return;
    }

    if (! ls->write_blocked && ls->write_paused)
    {
        ls->write_paused = false;
        if (ctpPrevGateEnter(t))
        {
            discard withLineLocked(l, tunnelPrevDownStreamResume, t);
            ctpPrevGateLeave(t);
        }
    }
}
