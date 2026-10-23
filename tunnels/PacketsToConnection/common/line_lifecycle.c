#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/signal_manager.h"

void ptcDetachTcpPcbLocked(ptc_lstate_t *ls)
{
    struct tcp_pcb *pcb = ls->tcp_pcb;

    if (pcb == NULL)
    {
        return;
    }

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    ls->write_poll_armed   = false;
    ls->write_retry_queued = false;
    ls->tcp_pcb            = NULL;
    ls->route_ctx          = NULL;
}

void ptcDetachUdpFlowLocked(ptc_lstate_t *ls)
{
    interface_route_context_t *route_ctx = ls->route_ctx;

    if (route_ctx == NULL)
    {
        ls->udp_pcb = NULL;
        return;
    }

    ptc_udp_flow_map_t_iter it = ptc_udp_flow_map_t_find(&route_ctx->udp_flows, ls->udp_flow_key);
    if (it.ref != ptc_udp_flow_map_t_end(&route_ctx->udp_flows).ref && it.ref->second == ls->line)
    {
        ptc_udp_flow_map_t_erase_at(&route_ctx->udp_flows, it);
    }

    if (ls->udp_pcb != NULL)
    {
        assert(route_ctx->udp_pcb != ls->udp_pcb);
        udp_recv(ls->udp_pcb, NULL, NULL);
        udp_remove(ls->udp_pcb);
    }

    ls->route_ctx = NULL;
    ls->udp_pcb   = NULL;
}

void ptcOwnedLineRegister(ptc_lstate_t *ls)
{
    ptc_tstate_t *state = tunnelGetState(ls->tunnel);
    const wid_t   wid   = lineGetWID(ls->line);
    assert(currentThreadOwnsWorker(wid));

    if (UNLIKELY(state->owned_lines == NULL || wid >= state->owned_worker_count || ls->owned_registered))
    {
        LOGF("PacketsToConnection: invalid owned-line registration state");
        abortProgramNow(1);
    }

    line_t *head   = state->owned_lines[wid];
    ls->owned_prev = NULL;
    ls->owned_next = head;
    if (head != NULL)
    {
        ptc_lstate_t *head_state = lineGetState(head, ls->tunnel);
        head_state->owned_prev   = ls->line;
    }
    state->owned_lines[wid] = ls->line;
    ls->owned_registered    = true;
}

void ptcOwnedLineUnregister(ptc_lstate_t *ls)
{
    if (UNLIKELY(! ls->owned_registered))
    {
        LOGF("PacketsToConnection: attempted to unregister a line absent from the owned-line registry");
        abortProgramNow(1);
    }

    ptc_tstate_t *state = tunnelGetState(ls->tunnel);
    const wid_t   wid   = lineGetWID(ls->line);
    assert(currentThreadOwnsWorker(wid));

    if (UNLIKELY(state->owned_lines == NULL || wid >= state->owned_worker_count))
    {
        LOGF("PacketsToConnection: invalid owned-line registry state during unregister");
        abortProgramNow(1);
    }

    if (ls->owned_prev != NULL)
    {
        ptc_lstate_t *previous = lineGetState(ls->owned_prev, ls->tunnel);
        previous->owned_next   = ls->owned_next;
    }
    else
    {
        assert(state->owned_lines[wid] == ls->line);
        state->owned_lines[wid] = ls->owned_next;
    }
    if (ls->owned_next != NULL)
    {
        ptc_lstate_t *next = lineGetState(ls->owned_next, ls->tunnel);
        next->owned_prev   = ls->owned_prev;
    }
    ls->owned_prev       = NULL;
    ls->owned_next       = NULL;
    ls->owned_registered = false;
}

bool ptcRequiredControlRefusedLocked(ptc_lstate_t *ls, const char *operation)
{
    bool aborted = false;

    assert(lineIsOnCurrentWorker(ls->line));
    assert(wwLwipEngineCurrent() == ls->engine);
    /* The caller is executing inside the owner engine. Stop the exact producer before
     * publishing the allocation-free owner-worker reconciliation. */
    if (ls->kind == kPtcLineKindTcp)
    {
        struct tcp_pcb *pcb = ls->tcp_pcb;
        ptcDetachTcpPcbLocked(ls);
        if (pcb != NULL)
        {
            tcp_abort(pcb);
            aborted = true;
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }

    ls->terminal_required = true;

    LOGE("PacketsToConnection: required owner control '%s' was refused; flow detached", operation);
    if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
    {
        abortProgramNow(1);
    }
    return aborted;
}

static void ptcCloseOwnedLine(tunnel_t *t, line_t *l, bool graceful_tcp, bool finish_next)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineRef(l);

    ptc_lstate_t *ls = lineGetState(l, t);

    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
    assert(entered);
    discard entered;
    if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL)
    {
        const ptc_tcp_drain_adopt_result_t adopted = graceful_tcp ? ptcTcpDrainAdoptLocked(t, ls) : kPtcTcpDrainFailed;

        if (adopted != kPtcTcpDrainAdopted)
        {
            struct tcp_pcb *pcb = ls->tcp_pcb;
            ptcDetachTcpPcbLocked(ls);
            if (pcb != NULL)
            {
                tcp_abort(pcb);
            }
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }
    wwLwipEngineLeave(ls->engine, previous);

    const bool send_finish = finish_next && ls->next_init_sent;
    ptcLinestateDestroy(ls);

    if (send_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    lineUnref(l);
}

void ptcCloseLineFromNetwork(tunnel_t *t, line_t *l)
{
    ptcCloseOwnedLine(t, l, true, true);
}

void ptcCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    /* next sent Finish, so this close must never reflect a callback to next. */
    ptcCloseOwnedLine(t, l, true, false);
}

void ptcCloseLineOverPendingLimit(tunnel_t *t, line_t *l)
{
    /*
     * next is still open and produced the excess, so it gets exactly one
     * Finish. The PCB is reset instead of drained - see the header note.
     */
    ptcCloseOwnedLine(t, l, false, true);
}

void ptcCloseLineForStop(tunnel_t *t, line_t *l)
{
    /*
     * PTC owns this normal line. Quiesce has already blocked ordinary next
     * callbacks, but chain hooks drain PTC before its next tunnel. An Init that
     * completed therefore still needs exactly one teardown Finish before the
     * owned line becomes dead and the next tunnel's line state is reclaimed.
     */
    ptcCloseOwnedLine(t, l, false, true);
}

void ptcDrainOwnedLinesOnCurrentWorker(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);

    assert(currentThreadOwnsWorker(wid));
    if (state->owned_lines == NULL || wid >= state->owned_worker_count)
    {
        return;
    }

    for (;;)
    {

        line_t *line = state->owned_lines[wid];
        if (line != NULL)
        {
            assert(lineIsAlive(line));
            lineRef(line);
        }

        if (line == NULL)
        {
            return;
        }

        ptcCloseLineForStop(t, line);
        lineUnref(line);
    }
}

void ptcDrainTerminalLinesOnCurrentWorker(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);

    assert(currentThreadOwnsWorker(wid));
    if (state->owned_lines == NULL || wid >= state->owned_worker_count)
    {
        return;
    }

    for (;;)
    {
        line_t *terminal = NULL;

        for (line_t *line = state->owned_lines[wid]; line != NULL;)
        {
            assert(lineIsAlive(line));
            ptc_lstate_t *ls = lineGetState(line, t);
            if (ls->terminal_required)
            {
                ls->terminal_required = false;
                lineRef(line);
                terminal = line;
                break;
            }
            line = ls->owned_next;
        }

        if (terminal == NULL)
        {
            return;
        }

        /* The producer PCB/map was already detached inside the owner engine. The
         * owner now performs line-state teardown, directionally legal Finish
         * (only if Init was sent), and the owner-only lineDestroy(). */
        ptcCloseLineForStop(t, terminal);
        lineUnref(terminal);
    }
}
