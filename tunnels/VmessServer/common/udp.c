#include "internal.h"

void vmessserverSetUdpBackendPaused(tunnel_t *t, line_t *remote_l, bool paused)
{
    vmessserver_lstate_t *remote   = lineGetState(remote_l, t);
    line_t               *client_l = remote->client_line;
    if (client_l == NULL || ! lineIsAlive(client_l))
        return;
    vmessserver_lstate_t *client = lineGetState(client_l, t);
    if (client->udp_remote_line != remote_l)
        return;
    client->udp_backend_paused = paused;
    vmessserverReconcileUdpSourcePermission(t, client_l);
}

static line_t *vmessserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, vmessserver_lstate_t *client_ls)
{
    if (client_ls->udp_remote_line != NULL && lineIsAlive(client_ls->udp_remote_line))
    {
        return client_ls->udp_remote_line;
    }

    /* Existing backends may receive final bytes; shutdown must not recreate them. */
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(client_l)))))
        return NULL;

    assert(addresscontextHasPort(&client_ls->udp_target));

    line_t               *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    vmessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    vmessserverLinestateInitialize(remote_ls, t, remote_l, kVmessServerLineKindUdpRemote);
    remote_ls->client_line          = client_l;
    remote_ls->client_line_ref_held = true;
    remote_ls->user_handle          = client_ls->user_handle;
    remote_ls->phase                = kVmessServerPhaseUdpConnecting;

    lineRef(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    addresscontextCopy(lineGetSourceAddressContext(remote_l), lineGetSourceAddressContext(client_l));
    lineCopyUsers(remote_l, client_l);
    vmessserverApplyDestinationContext(remote_l, &client_ls->udp_target, true);
    client_ls->udp_remote_line = remote_l;

    if (UNLIKELY(! lineCallWithRef(remote_l, tunnelNextUpStreamInit, t)))
    {
        return NULL;
    }
    /* The caller holds client_l throughout Init; callbacks can replace or
     * close either exact association. Replay existing receiver pressure onto
     * the newly initialized backend before it becomes an independent source. */
    if (UNLIKELY(! lineIsAlive(client_l)))
    {
        return NULL;
    }
    client_ls = lineGetState(client_l, t);
    if (UNLIKELY(client_ls->udp_remote_line != remote_l))
    {
        return NULL;
    }
    if (UNLIKELY(client_ls->response_paused && ! lineCallWithRef(remote_l, tunnelNextUpStreamPause, t)))
    {
        return NULL;
    }
    if (! lineIsAlive(client_l) || client_ls->tunnel != t || client_ls->udp_remote_line != remote_l)
        return NULL;
    return remote_l;
}

bool vmessserverStartUdpBranch(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, const address_context_t *target)
{
    addresscontextCopy(&ls->udp_target, target);
    ls->phase = kVmessServerPhaseUdpConnecting;

    lineRef(l);
    line_t *remote_l     = vmessserverGetOrCreateUdpRemoteLine(t, l, ls);
    bool    client_alive = lineIsAlive(l);
    lineUnref(l);

    if (UNLIKELY(! client_alive || ls->tunnel != t))
    {
        return false;
    }

    if (UNLIKELY(remote_l == NULL))
    {
        vmessserverCloseLineBidirectional(t, l);
        return false;
    }

    return true;
}

bool vmessserverDeliverDecoded(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (ls->next_finished)
    {
        lineReuseBuffer(line, payload);
        return false;
    }
    if (ls->request.command == kVmessCmdTcp)
    {
        if (! lineCallWithRefWithBuf(line, tunnelNextUpStreamPayload, t, payload))
            return false;
        return ((vmessserver_lstate_t *) lineGetState(line, t))->tunnel == t;
    }
    buffer_pool_t *pool = lineGetBufferPool(line);
    lineRef(line);
    line_t *remote = vmessserverGetOrCreateUdpRemoteLine(t, line, ls);
    if (! lineIsAlive(line) || ls->tunnel != t)
    {
        bufferpoolReuseBuffer(pool, payload);
        lineUnref(line);
        return false;
    }
    if (! remote)
    {
        bufferpoolReuseBuffer(pool, payload);
        vmessserverCloseLineBidirectional(t, line);
        lineUnref(line);
        return false;
    }
    discard lineCallWithRefWithBuf(remote, tunnelNextUpStreamPayload, t, payload);
    bool    alive = lineIsAlive(line) && ls->tunnel == t;
    lineUnref(line);
    return alive;
}
