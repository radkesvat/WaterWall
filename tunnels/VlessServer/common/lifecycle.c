#include "internal.h"

static void vlessserverDetachRemoteFromClient(vlessserver_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_ref_held)
    {
        if (lineIsAlive(client_line))
        {
            vlessserver_lstate_t *client_ls = lineGetState(client_line, remote_ls->tunnel);
            if (client_ls->udp_remote_line == remote_ls->line)
            {
                client_ls->udp_remote_line    = NULL;
                client_ls->udp_backend_paused = false;
            }
        }

        lineUnref(client_line);
    }

    remote_ls->client_line          = NULL;
    remote_ls->client_line_ref_held = false;
}

static bool vlessserverHasTcpUpstreamPeer(const vlessserver_lstate_t *ls)
{
    return ls->line_kind == kVlessServerLineKindClient &&
           (ls->phase == kVlessServerPhaseFallback || ls->phase == kVlessServerPhaseTcpConnecting ||
            ls->phase == kVlessServerPhaseTcpEstablished);
}

static void vlessserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    if (UNLIKELY(remote_ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    remote_ls->phase = kVlessServerPhaseClosing;
    lineRef(remote_l);
    /* Detach releases the persistent association reference. Retain the client
     * independently until the old remote is dead and permission is reconciled. */
    line_t *client_l = remote_ls->client_line;
    if (client_l != NULL && lineIsAlive(client_l))
        lineRef(client_l);
    else
        client_l = NULL;

    vlessserverDetachRemoteFromClient(remote_ls);
    vlessserverLinestateDestroy(remote_ls);

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
            vlessserverReconcileUdpSourcePermission(t, client_l);
        lineUnref(client_l);
    }
    lineUnref(remote_l);
}

static void vlessserverCloseOwnedUdpRemoteLine(tunnel_t *t, vlessserver_lstate_t *client_ls, bool close_next)
{
    line_t *remote_l = client_ls->udp_remote_line;

    if (remote_l == NULL || ! lineIsAlive(remote_l))
    {
        return;
    }

    vlessserverCloseUdpRemoteLineInternal(t, remote_l, close_next);
}

static void vlessserverCloseLine(tunnel_t *t, line_t *l, vlessserver_close_origin_t origin)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->line_kind == kVlessServerLineKindUdpRemote))
    {
        vlessserverCloseUdpRemoteLineInternal(t, l, origin != kVlessServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    bool      close_next = origin != kVlessServerCloseFromNext && vlessserverHasTcpUpstreamPeer(ls);
    bool      close_prev = origin != kVlessServerCloseFromPrev;
    bool      use_target = ls->phase == kVlessServerPhaseFallback;
    tunnel_t *target     = use_target ? ((vlessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel : NULL;

    if (origin == kVlessServerCloseFromPrev && use_target && target != NULL)
    {
        vlessserverCloseFallbackFromUpstream(t, l, ls, target);
        return;
    }

    ls->phase = kVlessServerPhaseClosing;
    lineRef(l);

    vlessserverCloseOwnedUdpRemoteLine(t, ls, origin != kVlessServerCloseFromNext);
    vlessserverLinestateDestroy(ls);

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

void vlessserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromPrev);
}

void vlessserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromNext);
}

void vlessserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseInternal);
}

void vlessserverTunnelstateDestroy(vlessserver_tstate_t *ts)
{
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
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}
