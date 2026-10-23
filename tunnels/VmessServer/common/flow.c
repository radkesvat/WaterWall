#include "internal.h"

static sbuf_t *encodeFrame(line_t *line, vmessserver_lstate_t *ls, const uint8_t *data, size_t size, bool eof,
                           wcrypto_status_t *status)
{
    buffer_pool_t *pool     = lineGetBufferPool(line);
    size_t         prefix   = ls->response_sent ? 0 : VMESS_RESPONSE_HEADER_SIZE;
    size_t         capacity = prefix + size + 18 + 16 + 63;
    sbuf_t        *frame    = bufferpoolGetBestFit(pool, (uint32_t) capacity, bufferpoolGetLargeBufferPadding(pool));
    size_t         written  = 0;
    *status                 = vmessBodySeal(
        &ls->output_crypto, data, size, eof, sbufGetMutablePtr(frame) + prefix, capacity - prefix, &written);
    if (*status != kWCryptoOk)
    {
        lineReuseBuffer(line, frame);
        return NULL;
    }
    if (prefix)
        memoryCopy(sbufGetMutablePtr(frame), ls->response_header, prefix);
    sbufSetLength(frame, (uint32_t) (prefix + written));
    ls->response_sent = true;
    return frame;
}

bool vmessserverSendTermination(tunnel_t *t, line_t *line)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (! ls->crypto_ready || ls->closing_output || ls->output_crypto.ended || ls->prev_finished)
        return true;
    ls->closing_output = true;
    wcrypto_status_t status;
    sbuf_t          *frame = encodeFrame(line, ls, NULL, 0, true, &status);
    if (! frame)
        return true;
    if (! sbufGetLength(frame))
    {
        lineReuseBuffer(line, frame);
        return true;
    }
    if (! lineCallWithRefWithBuf(line, tunnelPrevDownStreamPayload, t, frame))
        return false;
    return ((vmessserver_lstate_t *) lineGetState(line, t))->tunnel == t;
}

bool vmessserverDrainResponse(tunnel_t *t, line_t *line, bool admitted)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (ls->response_dispatching || ls->closing_output)
        return true;
    lineRef(line);
    buffer_pool_t *pool       = lineGetBufferPool(line);
    ls->response_dispatching  = true;
    const bool tcp            = ls->request.command == kVmessCmdTcp;
    size_t     admitted_count = admitted ? bufferqueueGetBufCount(&ls->pending_down) : 0;
    while (tcp || ls->finish_pending || admitted_count != 0 || ! ls->response_paused)
    {
        sbuf_t *out = bufferqueuePopFrontReserved(&ls->pending_down, &ls->response_reservation);
        if (! out)
            break;
        if (admitted_count)
            --admitted_count;
        size_t available = sbufGetLength(out);
        if (! available || (! tcp && available > vmessBodyMaxPlaintext(&ls->output_crypto)))
        {
            bufferbudgetReservationRelease(&ls->response_reservation);
            lineReuseBuffer(line, out);
            continue;
        }
        while (available)
        {
            size_t           take = tcp ? min(available, (size_t) 16384) : available;
            wcrypto_status_t status;
            sbuf_t          *frame = encodeFrame(line, ls, sbufGetRawPtr(out), take, false, &status);
            if (! frame)
            {
                bufferbudgetReservationRelease(&ls->response_reservation);
                lineReuseBuffer(line, out);
                if (status == kVmessCounterExhausted && ! vmessserverSendTermination(t, line))
                {
                    lineUnref(line);
                    return false;
                }
                vmessserverCloseLineBidirectional(t, line);
                lineUnref(line);
                return false;
            }
            sbufShiftRight(out, (uint32_t) take);
            available -= take;
            bufferbudgetReservationSetBytes(&ls->response_reservation, available);
            tunnelPrevDownStreamPayload(t, line, frame);
            if (! lineIsAlive(line) || ((vmessserver_lstate_t *) lineGetState(line, t))->tunnel != t)
            {
                bufferpoolReuseBuffer(pool, out);
                lineUnref(line);
                return false;
            }
            ls = lineGetState(line, t);
            if (ls->closing_output)
            {
                bufferbudgetReservationRelease(&ls->response_reservation);
                lineReuseBuffer(line, out);
                ls->response_dispatching = false;
                lineUnref(line);
                return true;
            }
        }
        bufferbudgetReservationRelease(&ls->response_reservation);
        lineReuseBuffer(line, out);
    }
    ls->response_dispatching = false;
    if (ls->finish_pending)
    {
        ls->finish_pending = false;
        vmessserverCloseLineFromDownstream(t, line);
        lineUnref(line);
        return false;
    }
    lineUnref(line);
    return true;
}

bool vmessserverForwardResponse(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (ls->closing_output || ls->next_finished || ! ls->crypto_ready)
    {
        lineReuseBuffer(line, buf);
        return true;
    }
    bool older = bufferqueueGetBufCount(&ls->pending_down) != 0;
    if (! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        lineReuseBuffer(line, buf);
        vmessserverCloseLineBidirectional(t, line);
        return false;
    }
    return vmessserverDrainResponse(t, line, ! older);
}

void vmessserverReconcileUdpSourcePermission(tunnel_t *t, line_t *client_l)
{
    vmessserver_lstate_t *client = lineGetState(client_l, t);
    if (client->phase == kVmessServerPhaseClosing || client->tunnel != t ||
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

void vmessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls)
{
    line_t *client = l;
    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        ls->phase = kVmessServerPhaseUdpEstablished;
        client    = ls->client_line;
        if (UNLIKELY(client == NULL || ! lineIsAlive(client)))
        {
            vmessserverCloseLineBidirectional(t, l);
            return;
        }
    }
    lineRef(l);
    lineRef(client);
    vmessserver_lstate_t *client_ls = lineGetState(client, t);
    client_ls->phase                = client == l ? kVmessServerPhaseTcpEstablished : kVmessServerPhaseUdpEstablished;
    if (client == l || ! client_ls->transport_est_sent)
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
            if (client_ls->tunnel == t && client_ls->phase != kVmessServerPhaseClosing)
            {
                client_ls->response_dispatching = was_dispatching;
                discard vmessserverDrainResponse(t, client, false);
            }
        }
    }
    lineUnref(client);
    lineUnref(l);
}
