#include "auth.h"
#include "internal.h"

static void vmessserverDetachRemoteFromClient(vmessserver_lstate_t *remote_ls)
{
    line_t               *client_line = remote_ls->client_line;
    vmessserver_tstate_t *ts          = tunnelGetState(remote_ls->tunnel);
    if (remote_ls->owned_prev != NULL)
        remote_ls->owned_prev->owned_next = remote_ls->owned_next;
    else
        ts->owned_backends[lineGetWID(remote_ls->line)] = remote_ls->owned_next;
    if (remote_ls->owned_next != NULL)
        remote_ls->owned_next->owned_prev = remote_ls->owned_prev;
    remote_ls->owned_prev = remote_ls->owned_next = NULL;

    if (client_line != NULL && remote_ls->client_line_ref_held)
    {
        /* The persistent association reference preserves allocation. If the
         * creator marks the parent dead during a backend Finish, its matching
         * Closing state still belongs to the outer synchronous owner drain.
         * Unlink that retained storage without sending callbacks to the parent. */
        vmessserver_lstate_t *client_ls = lineGetState(client_line, remote_ls->tunnel);
        if (client_ls->tunnel == remote_ls->tunnel &&
            (lineIsAlive(client_line) || client_ls->phase == kVmessServerPhaseClosing) &&
            vmessserverUdpMember(remote_ls->tunnel, client_ls, remote_ls->line))
        {
            if (client_ls->packetaddr)
            {
                client_ls->udp_destinations[remote_ls->udp_slot] = NULL;
                assert(client_ls->udp_destination_count != 0);
                --client_ls->udp_destination_count;
            }
            else
                client_ls->udp_remote_line = NULL;
            if (remote_ls->backend_paused)
            {
                assert(client_ls->paused_backends != 0);
                --client_ls->paused_backends;
            }
            client_ls->udp_backend_paused = client_ls->paused_backends != 0;
        }

        lineUnref(client_line);
    }

    remote_ls->client_line          = NULL;
    remote_ls->client_line_ref_held = false;
}

static bool vmessserverHasTcpUpstreamPeer(const vmessserver_lstate_t *ls)
{
    return ls->line_kind == kVmessServerLineKindClient &&
           (ls->phase == kVmessServerPhaseFallback || ls->phase == kVmessServerPhaseTcpConnecting ||
            ls->phase == kVmessServerPhaseTcpEstablished);
}

void vmessserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    vmessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    if (UNLIKELY(remote_ls->phase == kVmessServerPhaseClosing))
    {
        return;
    }

    remote_ls->phase = kVmessServerPhaseClosing;
    lineRef(remote_l);
    /* Detach releases the persistent association reference. Retain the client
     * independently until the old remote is dead and permission is reconciled. */
    line_t *client_l = remote_ls->client_line;
    if (client_l != NULL && lineIsAlive(client_l))
        lineRef(client_l);
    else
        client_l = NULL;

    vmessserverDetachRemoteFromClient(remote_ls);
    vmessserverLinestateDestroy(remote_ls);

    if (close_next && LIKELY(lineIsAlive(remote_l)))
    {
        tunnelNextUpStreamFinish(t, remote_l);
    }

    if (LIKELY(lineIsAlive(remote_l)))
    {
        lineDestroy(remote_l);
    }

    if (client_l != NULL)
    {
        if (lineIsAlive(client_l))
            vmessserverReconcileUdpSourcePermission(t, client_l);
        lineUnref(client_l);
    }
    lineUnref(remote_l);
}

static void vmessserverCloseOwnedUdpRemoteLine(tunnel_t *t, vmessserver_lstate_t *client_ls, bool close_next)
{
    if (client_ls->packetaddr)
    {
        /* Authenticated policy/replay/admission refusal can close before the
         * destination table is committed. No backend ownership exists yet. */
        if (client_ls->udp_destinations == NULL)
        {
            assert(client_ls->udp_destination_count == 0);
            return;
        }
        const vmessserver_tstate_t *ts = tunnelGetState(t);
        /* No iterator/raw sibling pointer survives a callback. Admission was
         * closed by the carrier's Closing phase before this drain begins. */
        for (;;)
        {
            line_t *remote = NULL;
            for (size_t i = 0; i < ts->packetaddr_max_destinations; ++i)
                if (client_ls->udp_destinations[i] != NULL)
                {
                    remote = client_ls->udp_destinations[i];
                    break;
                }
            if (remote == NULL)
                return;
            vmessserverCloseUdpRemoteLineInternal(t, remote, true);
        }
    }
    line_t *remote_l = client_ls->udp_remote_line;

    if (remote_l == NULL || ! lineIsAlive(remote_l))
    {
        return;
    }

    vmessserverCloseUdpRemoteLineInternal(t, remote_l, close_next);
}

static void vmessserverCloseLine(tunnel_t *t, line_t *l, vmessserver_close_origin_t origin)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->line_kind == kVmessServerLineKindUdpRemote))
    {
        vmessserverCloseUdpRemoteLineInternal(t, l, origin != kVmessServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing))
    {
        return;
    }

    ls->prev_finished |= origin == kVmessServerCloseFromPrev;
    ls->next_finished |= origin == kVmessServerCloseFromNext;
    if (origin == kVmessServerCloseFromNext && ls->crypto_ready)
    {
        /* Finish closes next immediately, but accepted replies still precede
         * EOF. The current response/Est callback owns the eventual drain. */
        if (ls->response_dispatching)
        {
            ls->finish_pending = true;
            return;
        }
        if (bufferqueueGetBufCount(&ls->pending_down) != 0)
        {
            ls->finish_pending = true;
            discard vmessserverDrainResponse(t, l, true);
            return;
        }
        if (! vmessserverSendTermination(t, l))
            return;
    }
    bool      close_next = ! ls->next_finished && vmessserverHasTcpUpstreamPeer(ls);
    bool      close_prev = ! ls->prev_finished;
    bool      use_target = ls->phase == kVmessServerPhaseFallback;
    tunnel_t *target     = use_target ? ((vmessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel : NULL;

    if (origin == kVmessServerCloseFromPrev && use_target && target != NULL)
    {
        vmessserverCloseFallbackFromUpstream(t, l, ls, target);
        return;
    }

    ls->phase = kVmessServerPhaseClosing;
    vmessserverReason(ls, kVmessServerReasonNormal);
    lineRef(l);

    vmessserverCloseOwnedUdpRemoteLine(t, ls, origin != kVmessServerCloseFromNext);
    vmessserverLinestateDestroy(ls);

    if (close_next && LIKELY(lineIsAlive(l)))
    {
        if (use_target && target != NULL)
        {
            tunnelUpStreamFin(target, l);
        }
        else
        {
            tunnelNextUpStreamFinish(t, l);
        }
    }

    if (close_prev && LIKELY(lineIsAlive(l)))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnref(l);
}

void vmessserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    vmessserverCloseLine(t, l, kVmessServerCloseFromPrev);
}

void vmessserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    vmessserverCloseLine(t, l, kVmessServerCloseFromNext);
}

void vmessserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    vmessserverCloseLine(t, l, kVmessServerCloseInternal);
}

void vmessserverTunnelstateDestroy(vmessserver_tstate_t *ts)
{
    vmessserverAuthDestroy(ts->auth);
    vmessReplayDestroy(ts->replay);
    if (ts->user_controller_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(ts->user_controller_tunnel);
        ts->user_controller_tunnel = NULL;
    }

    ts->user_controller_node.instance = NULL;
    memoryFree(ts->user_controller_node.name);
    memoryFree(ts->user_controller_node.type);
    memoryFree(ts->user_controller_node.next);
    memoryZero(&ts->user_controller_node, sizeof(ts->user_controller_node));

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        memoryFree(ts->users[i].username);
    }
    memoryFree(ts->users);
    if (ts->owned_backends != NULL)
        for (size_t i = 0; i < getWorkersCount(); ++i)
            assert(ts->owned_backends[i] == NULL);
    memoryFree(ts->owned_backends);
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}
