#include "internal.h"

void vlessserverSetUdpBackendPaused(tunnel_t *t, line_t *remote_l, bool paused)
{
    vlessserver_lstate_t *remote   = lineGetState(remote_l, t);
    line_t               *client_l = remote->client_line;
    if (client_l == NULL || ! lineIsAlive(client_l))
        return;
    vlessserver_lstate_t *client = lineGetState(client_l, t);
    if (client->udp_remote_line != remote_l)
        return;
    client->udp_backend_paused = paused;
    vlessserverReconcileUdpSourcePermission(t, client_l);
}

static line_t *vlessserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, vlessserver_lstate_t *client_ls)
{
    if (client_ls->udp_remote_line != NULL && lineIsAlive(client_ls->udp_remote_line))
    {
        return client_ls->udp_remote_line;
    }

    /* Existing backends may receive final bytes; shutdown must not recreate them. */
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(client_l)))))
        return NULL;

    if (UNLIKELY(! addresscontextHasPort(&client_ls->udp_target)))
    {
        return NULL;
    }

    line_t               *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    vlessserverLinestateInitialize(remote_ls, t, remote_l, kVlessServerLineKindUdpRemote);
    remote_ls->client_line          = client_l;
    remote_ls->client_line_ref_held = true;
    remote_ls->user_handle          = client_ls->user_handle;
    remote_ls->phase                = kVlessServerPhaseUdpConnecting;

    lineRef(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    lineCopyUsers(remote_l, client_l);
    vlessserverApplyDestinationContext(remote_l, &client_ls->udp_target, true);
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

bool vlessserverStartUdpBranch(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, const address_context_t *target)
{
    addresscontextCopy(&ls->udp_target, target);
    ls->phase = kVlessServerPhaseUdpConnecting;

    lineRef(l);
    line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
    bool    client_alive = lineIsAlive(l);
    lineUnref(l);

    if (UNLIKELY(! client_alive || ls->tunnel != t))
    {
        return false;
    }

    if (UNLIKELY(remote_l == NULL))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    return true;
}

bool vlessserverDrainUdpPackets(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    while (ls->input_bytes != 0)
    {
        if (! vlessserverGatherHeader(ls, 2))
            return true;
        uint16_t packet_size = ((uint16_t) ls->header[0] << 8U) | ls->header[1];
        if (packet_size == 0)
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
        if (ls->input_bytes - 2U < packet_size)
            return true;
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *packet = vlessserverExtractUdpBody(ls, packet_size);

        lineRef(l);
        line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
        bool    client_alive = lineIsAlive(l);
        lineUnref(l);

        if (UNLIKELY(! client_alive || ls->tunnel != t))
        {
            bufferpoolReuseBuffer(pool, packet);
            return false;
        }

        if (UNLIKELY(remote_l == NULL))
        {
            bufferpoolReuseBuffer(pool, packet);
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }

        if (ls->phase == kVlessServerPhaseUdpWaitPacket)
        {
            ls->phase = kVlessServerPhaseUdpConnecting;
        }

        lineRef(l);
        bool remote_alive = lineCallWithRefWithBuf(remote_l, tunnelNextUpStreamPayload, t, packet);
        client_alive      = lineIsAlive(l);
        lineUnref(l);

        if (UNLIKELY(! client_alive || ls->tunnel != t))
        {
            return false;
        }

        if (UNLIKELY(! remote_alive))
        {
            continue;
        }
    }

    return true;
}

bool vlessserverWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);

    if (UNLIKELY(payload == 0 || payload > kVlessServerUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kVlessServerUdpHeaderLen))
    {
        buffer_pool_t *pool    = lineGetBufferPool(l);
        uint16_t       padding = max(bufferpoolGetLargeBufferPadding(pool), kVlessServerUdpHeaderLen);
        sbuf_t        *wrapped = sbufIsSplice(buf) ? bufferpoolGetSpliceBuffer(pool) : NULL;
        if (wrapped != NULL && sbufGetLeftCapacity(wrapped) < padding)
        {
            bufferpoolReuseBuffer(pool, wrapped);
            wrapped = NULL;
        }
        wrapped = sbufMoveRangeTo(pool, buf, wrapped, payload, payload, padding);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    sbufShiftLeft(buf, kVlessServerUdpHeaderLen);

    *buf_io = buf;

    uint8_t *ptr    = sbufGetMutablePtr(buf);
    uint16_t len_be = htobe16((uint16_t) payload);
    memoryCopy(ptr, &len_be, sizeof(len_be));
    return true;
}
