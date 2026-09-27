#include "internal.h"

bool vlessserverDrainResponse(tunnel_t *t, line_t *l, bool admitted)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->response_dispatching)
    {
        return true;
    }
    lineRef(l);
    ls->response_dispatching = true;
    while (admitted || ! ls->response_paused)
    {
        sbuf_t *out = bufferqueuePopFront(&ls->pending_down);
        if (out == NULL)
        {
            break;
        }
        if (! ls->response_sent)
        {
            uint32_t body_len = sbufGetLength(out);
            if (UNLIKELY(body_len == 0))
            {
                lineReuseBuffer(l, out);
                continue;
            }
            /* Keep the header and complete first reply in one ordinary buffer.
             * Reuse its advertised headroom when no materialization is needed. */
            if (! sbufIsSplice(out) && sbufGetLeftCapacity(out) >= kVlessServerResponseLen)
            {
                sbufShiftLeft(out, kVlessServerResponseLen);
            }
            else
            {
                buffer_pool_t *pool  = lineGetBufferPool(l);
                uint64_t       total = (uint64_t) kVlessServerResponseLen + body_len;
                sbuf_t        *first = bufferpoolTryGetBestFit(pool, total, bufferpoolGetLargeBufferPadding(pool));
                if (UNLIKELY(first == NULL))
                {
                    lineReuseBuffer(l, out);
                    vlessserverCloseLineBidirectional(t, l);
                    lineUnref(l);
                    return false;
                }
                sbufReadRangeToMemory(out, sbufGetMutablePtr(first) + kVlessServerResponseLen, body_len);
                sbufSetLength(first, (uint32_t) total);
                lineReuseBuffer(l, out);
                out = first;
            }
            uint8_t *bytes    = sbufGetMutablePtr(out);
            bytes[0]          = kVlessVersion;
            bytes[1]          = 0;
            ls->response_sent = true;
        }
        tunnelPrevDownStreamPayload(t, l, out);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            lineUnref(l);
            return false;
        }
        ls = lineGetState(l, t);
        if (UNLIKELY(ls->tunnel != t || ls->phase == kVlessServerPhaseClosing))
        {
            lineUnref(l);
            return false;
        }
    }
    ls->response_dispatching = false;
    lineUnref(l);
    return true;
}

bool vlessserverForwardResponse(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessserver_lstate_t *ls        = lineGetState(l, t);
    bool                  has_older = bufferqueueGetBufCount(&ls->pending_down) != 0;
    if (ls->response_sent && ! ls->response_dispatching && ! has_older)
    {
        return lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
    }
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_down, &buf)))
    {
        lineReuseBuffer(l, buf);
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }
    /* A newly admitted reply can include its required response header. A
     * preexisting delayed FIFO remains an independent Pause-aware drain. */
    return vlessserverDrainResponse(t, l, ! has_older);
}

void vlessserverReconcileUdpSourcePermission(tunnel_t *t, line_t *client_l)
{
    vlessserver_lstate_t *client = lineGetState(client_l, t);
    if (client->phase == kVlessServerPhaseClosing || client->tunnel != t ||
        ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(client_l))) ||
        client->udp_backend_paused == client->udp_source_pause_sent)
        return;
    /* Publish before reentry. Resume may replace the backend and acquire a new
     * hold, or destroy this client; nothing writes state after the callback. */
    client->udp_source_pause_sent = client->udp_backend_paused;
    if (client->udp_source_pause_sent)
        discard lineCallWithRef(client_l, tunnelPrevDownStreamPause, t);
    else
        discard lineCallWithRef(client_l, tunnelPrevDownStreamResume, t);
}

void vlessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    line_t *client = l;
    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        ls->phase = kVlessServerPhaseUdpEstablished;
        client    = ls->client_line;
        if (UNLIKELY(client == NULL || ! lineIsAlive(client)))
        {
            vlessserverCloseLineBidirectional(t, l);
            return;
        }
    }
    lineRef(l);
    lineRef(client);
    vlessserver_lstate_t *client_ls = lineGetState(client, t);
    client_ls->phase                = client == l ? kVlessServerPhaseTcpEstablished : kVlessServerPhaseUdpEstablished;
    if (! client_ls->transport_est_sent)
    {
        bool was_dispatching            = client_ls->response_dispatching;
        client_ls->transport_est_sent   = true;
        client_ls->response_dispatching = true;
        tunnelPrevDownStreamEst(t, client);
        /* An owned UDP backend may finish while the client association survives.
         * Its death must not strand the client's response-ordering guard. */
        if (lineIsAlive(client))
        {
            client_ls = lineGetState(client, t);
            if (client_ls->tunnel == t && client_ls->phase != kVlessServerPhaseClosing)
            {
                client_ls->response_dispatching = was_dispatching;
                discard vlessserverDrainResponse(t, client, false);
            }
        }
    }
    lineUnref(client);
    lineUnref(l);
}
