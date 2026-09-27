#include "internal.h"

#include "loggers/network_logger.h"

void socks5serverRequireCurrentLineWorker(const line_t *l, const char *callback_name)
{
    if (UNLIKELY(l == NULL || ! lineIsOnCurrentEventWorker(l)))
    {
        LOGF("Socks5Server: %s arrived outside its line owner worker",
             callback_name != NULL ? callback_name : "flow callback");
        abortProgramNow(1);
    }
}

static void socks5serverDestroyInternalUserController(socks5server_tstate_t *ts)
{
    if (ts->user_controller_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(ts->user_controller_tunnel);
        ts->user_controller_tunnel = NULL;
    }

    ts->user_controller_node.instance = NULL;
}

static void socks5serverClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

void socks5serverDetachRemoteFromClient(socks5server_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_ref_held)
    {
        if (lineIsAlive(client_line))
        {
            socks5server_lstate_t         *client_ls = lineGetState(client_line, remote_ls->tunnel);
            socks5server_remote_map_t_iter it =
                socks5server_remote_map_t_find(&client_ls->udp_remote_lines, remote_ls->remote_key);
            if (it.ref != socks5server_remote_map_t_end(&client_ls->udp_remote_lines).ref &&
                it.ref->second == remote_ls->line)
            {
                socks5server_remote_map_t_erase_at(&client_ls->udp_remote_lines, it);
            }
        }

        lineUnref(client_line);
    }

    remote_ls->client_line          = NULL;
    remote_ls->client_line_ref_held = false;
}

void socks5serverTunnelstateDestroy(socks5server_tstate_t *ts)
{
    socks5serverDestroyInternalUserController(ts);
    socks5serverClearInternalNode(&ts->user_controller_node);

    if (ts->worker_associations != NULL)
    {
        for (wid_t wid = 0; wid < ts->workers_count; ++wid)
        {
            assert(socks5server_assoc_map_t_size(&ts->worker_associations[wid]) == 0);
            c_foreach(it, socks5server_assoc_map_t, ts->worker_associations[wid])
            {
                socks5serverAssocEntryFreeCreds(&it.ref->second);
            }
            socks5server_assoc_map_t_drop(&ts->worker_associations[wid]);
        }
        memoryFree(ts->worker_associations);
        ts->worker_associations = NULL;
    }

    if (ts->udp_reply_ipv4 != NULL)
    {
        memoryFree(ts->udp_reply_ipv4);
        ts->udp_reply_ipv4 = NULL;
    }

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

static bool socks5serverControlHasUpstreamPeer(const socks5server_lstate_t *ls)
{
    return ls->next_initialized;
}

static void socks5serverMarkControlFinishedSide(socks5server_lstate_t *ls, socks5server_close_origin_t origin)
{
    if (origin == kSocks5ServerCloseFromPrev)
    {
        ls->prev_finished = true;
    }
    else if (origin == kSocks5ServerCloseFromNext)
    {
        ls->next_finished = true;
    }
}

void socks5serverCloseControlLine(tunnel_t *t, line_t *l, socks5server_close_origin_t origin, int reply_code,
                                  sbuf_t *final_reply)
{
    socks5serverRequireCurrentLineWorker(l, "control close");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kSocks5ServerPhaseClosing && origin == kSocks5ServerCloseInternal)
    {
        if (final_reply != NULL)
            lineReuseBuffer(l, final_reply);
        return;
    }

    bool has_peer   = socks5serverControlHasUpstreamPeer(ls);
    bool pre_est    = ls->phase == kSocks5ServerPhaseConnectWaitEst;
    bool close_next = origin != kSocks5ServerCloseFromNext && has_peer;
    bool close_prev = origin != kSocks5ServerCloseFromPrev;
    bool send_reply = ls->phase != kSocks5ServerPhaseClosing && close_prev && reply_code >= 0 &&
                      ! ls->connect_reply_sent && (pre_est || ! has_peer);

    socks5serverMarkControlFinishedSide(ls, origin);

    ls->phase = kSocks5ServerPhaseClosing;
    lineRef(l);

    socks5serverUnregisterUdpAssociation(t, ls);
    if (! lineIsAlive(l) || ls->kind != kSocks5ServerLineKindControlTcp)
    {
        if (final_reply != NULL)
            bufferpoolReuseBuffer(lineGetBufferPool(l), final_reply);
        lineUnref(l);
        return;
    }

    if (send_reply || final_reply != NULL)
    {
        sbuf_t *reply =
            final_reply != NULL ? final_reply : socks5serverCreateCommandReply(l, (uint8_t) reply_code, NULL);
        if (reply != NULL)
        {
            ls->connect_reply_sent = true;
            tunnelPrevDownStreamPayload(t, l, reply);
            if (! lineIsAlive(l) || ls->kind != kSocks5ServerLineKindControlTcp)
            {
                lineUnref(l);
                return;
            }
        }
    }

    bool send_next_finish = close_next && ! ls->next_finished;
    bool send_prev_finish = close_prev && ! ls->prev_finished;

    socks5serverLinestateDestroy(ls);

    if (send_next_finish && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (send_prev_finish && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnref(l);
}

void socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseFromPrev, -1, NULL);
}

void socks5serverCloseControlLineFromDownstream(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseFromNext, kSocks5ReplyGeneralFailure, NULL);
}

void socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, -1, NULL);
}

/* Retain the provider client across remote Finish: it may close this different line. */
static bool socks5serverDrainUdpClientRemoteLines(tunnel_t *t, line_t *client_l, socks5server_lstate_t *client_ls)
{
    assert(client_l != NULL && client_ls != NULL);
    if (UNLIKELY(! lineIsAlive(client_l)))
    {
        return false;
    }

    lineRef(client_l);

    while (true)
    {
        if (! lineIsAlive(client_l))
        {
            lineUnref(client_l);
            return false;
        }

        /* Re-read after every potentially re-entrant remote callback. */
        client_ls = lineGetState(client_l, t);
        if (socks5server_remote_map_t_size(&client_ls->udp_remote_lines) == 0)
        {
            lineUnref(client_l);
            return true;
        }

        line_t *remote_l = NULL;
        c_foreach(it, socks5server_remote_map_t, client_ls->udp_remote_lines)
        {
            remote_l = it.ref->second;
            break;
        }

        if (UNLIKELY(remote_l == NULL || ! lineIsAlive(remote_l)))
        {
            LOGF("Socks5Server: UDP remote registry contains a dead or null line during client teardown");
            abortProgramNow(1);
        }

        socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);
        if (UNLIKELY(remote_ls->client_line != client_l || ! remote_ls->client_line_ref_held))
        {
            LOGF("Socks5Server: UDP remote registry contains a line without its client ownership link");
            abortProgramNow(1);
        }

        lineRef(remote_l);
        socks5serverDetachRemoteFromClient(remote_ls);
        socks5serverLinestateDestroy(remote_ls);
        tunnelNextUpStreamFinish(t, remote_l);
        if (UNLIKELY(! lineIsAlive(remote_l)))
        {
            LOGF("Socks5Server: next/upstream tunnel destroyed a Socks5Server-owned UDP remote during Finish");
            abortProgramNow(1);
        }
        lineDestroy(remote_l);
        lineUnref(remote_l);

        if (! lineIsAlive(client_l))
        {
            lineUnref(client_l);
            return false;
        }
    }
}

void socks5serverRejectUdpClientLine(tunnel_t *t, line_t *client_l)
{
    socks5serverRequireCurrentLineWorker(client_l, "UDP client rejection");

    socks5server_lstate_t *client_ls = lineGetState(client_l, t);
    if (client_ls->kind != kSocks5ServerLineKindUdpClient)
    {
        return;
    }

    if (! socks5serverDrainUdpClientRemoteLines(t, client_l, client_ls))
    {
        return;
    }

    socks5serverLinestateDestroy(client_ls);
    socks5serverLinestateInitialize(lineGetState(client_l, t), t, client_l, kSocks5ServerLineKindRejected);
}

static void socks5serverCloseUdpClientLineInternal(tunnel_t *t, line_t *client_l, bool close_prev)
{
    socks5serverRequireCurrentLineWorker(client_l, "UDP client close");

    socks5server_lstate_t *client_ls = lineGetState(client_l, t);

    if (! socks5serverDrainUdpClientRemoteLines(t, client_l, client_ls))
    {
        return;
    }

    socks5serverLinestateDestroy(client_ls);
    if (close_prev)
    {
        tunnelPrevDownStreamFinish(t, client_l);
    }
}

void socks5serverCloseUdpClientLineFromUpstream(tunnel_t *t, line_t *client_l)
{
    socks5serverCloseUdpClientLineInternal(t, client_l, false);
}

void socks5serverCloseUdpClientLine(tunnel_t *t, line_t *client_l)
{
    socks5serverCloseUdpClientLineInternal(t, client_l, true);
}

void socks5serverCloseUdpRemoteLine(tunnel_t *t, line_t *remote_l)
{
    socks5serverRequireCurrentLineWorker(remote_l, "UDP remote close");
    socks5server_lstate_t *remote_ls = lineGetState(remote_l, t);

    lineRef(remote_l);
    socks5serverDetachRemoteFromClient(remote_ls);
    socks5serverLinestateDestroy(remote_ls);
    tunnelNextUpStreamFinish(t, remote_l);
    if (UNLIKELY(! lineIsAlive(remote_l)))
    {
        LOGF("Socks5Server: next/upstream tunnel destroyed a Socks5Server-owned UDP remote during Finish");
        abortProgramNow(1);
    }
    lineDestroy(remote_l);
    lineUnref(remote_l);
}
