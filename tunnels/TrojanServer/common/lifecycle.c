#include "structure.h"

static bool trojanserverHasUpstreamPeer(const trojanserver_lstate_t *ls)
{
    return ls->branch == kTrojanServerBranchFallback || ls->phase == kTrojanServerPhaseTcpConnecting ||
           ls->phase == kTrojanServerPhaseTcpEstablished;
}

static void trojanserverCloseLine(tunnel_t *t, line_t *l, trojanserver_close_origin_t origin)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        trojanserverCloseUdpRemoteLineInternal(t, l, origin != kTrojanServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    bool      has_peer   = trojanserverHasUpstreamPeer(ls);
    bool      close_next = origin != kTrojanServerCloseFromNext && has_peer;
    bool      close_prev = origin != kTrojanServerCloseFromPrev;
    bool      use_target = ls->branch == kTrojanServerBranchFallback;
    tunnel_t *target     = use_target ? trojanserverSelectedUpstream(t, ls) : NULL;

    if (origin == kTrojanServerCloseFromPrev && use_target && target != NULL)
    {
        trojanserverCloseFallbackFromUpstream(t, l, ls, target);
        return;
    }

    ls->phase = kTrojanServerPhaseClosing;
    lineRef(l);
    trojanserverReleaseBuffers(ls);
    trojanserverCloseUdpRemoteLines(t, ls);
    trojanserverLinestateDestroy(ls);

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

void trojanserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseFromPrev);
}

void trojanserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseFromNext);
}

void trojanserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    trojanserverCloseLine(t, l, kTrojanServerCloseInternal);
}

void trojanserverTunnelstateDestroy(trojanserver_tstate_t *ts)
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
        memoryZero(ts->users[i].sha224, sizeof(ts->users[i].sha224));
        memoryFree(ts->users[i].username);
        memoryFree(ts->users[i].password);
    }
    memoryFree(ts->users);

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}
