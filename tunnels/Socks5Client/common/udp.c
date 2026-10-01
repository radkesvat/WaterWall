#include "internal.h"

#include "loggers/network_logger.h"

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
}

static line_t *createInternalLine(tunnel_t *t, line_t *application_l, socks5client_line_kind_t kind)
{
    line_t *inner_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(application_l));

    socks5client_lstate_t *inner_ls = lineGetState(inner_l, t);
    socks5clientLinestateInitialize(inner_ls, t, inner_l, kind);
    inner_ls->application_line = application_l;

    return inner_l;
}

bool socks5clientForwardUdpPayloadToRelay(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls,
                                          sbuf_t *buf)
{
    if (application_ls->udp_line == NULL || ! lineIsAlive(application_ls->udp_line))
    {
        lineReuseBuffer(application_l, buf);
        return false;
    }

    if (! socks5clientWrapUdpPayload(application_l, &buf, &application_ls->target_addr))
    {
        lineReuseBuffer(application_l, buf);
        return false;
    }

    return lineCallWithRefWithBuf(application_ls->udp_line, tunnelNextUpStreamPayload, t, buf);
}

bool socks5clientTryEstablishUdpApplication(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls)
{
    if (! application_ls->udp_control_ready || ! application_ls->udp_relay_ready)
        return true;
    application_ls->phase = kSocks5ClientPhaseEstablished;
    return socks5clientDrainPending(t, application_l);
}

bool socks5clientStartUdpRelayLine(tunnel_t *t, line_t *control_l, socks5client_lstate_t *control_ls,
                                   const address_context_t *relay_addr, bool *control_alive_out)
{
    *control_alive_out = true;
    lineRef(control_l);

    line_t *application_l = control_ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(control_l);
        return false;
    }

    lineRef(application_l);

    socks5client_lstate_t *application_ls = lineGetState(application_l, t);
    line_t                *udp_l          = createInternalLine(t, application_l, kSocks5ClientLineKindUdpRelay);

    addresscontextCopy(lineGetDestinationAddressContext(udp_l), relay_addr);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(udp_l), IP_PROTO_UDP);
    addresscontextSetDestinationPinned(lineGetDestinationAddressContext(udp_l), true);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(udp_l), IP_PROTO_UDP);

    application_ls->udp_line = udp_l;

    if (! lineCallWithRef(udp_l, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(application_l))
        {
            application_ls->udp_line = NULL;
        }
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(application_l);
        lineUnref(control_l);
        return false;
    }

    if (lineIsAlive(application_l) && application_ls->prev_paused &&
        ! lineCallWithRef(udp_l, tunnelNextUpStreamPause, t))
    {
        // The callback may have reclaimed udp_l; only our retained application/control remain accessible.
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(application_l);
        lineUnref(control_l);
        return false;
    }

    bool application_alive = lineIsAlive(application_l);
    *control_alive_out     = lineIsAlive(control_l);
    if (! application_alive || ! *control_alive_out)
    {
        socks5clientCloseOwnedLine(t, udp_l);
    }
    lineUnref(application_l);
    lineUnref(control_l);

    if (! application_alive || ! *control_alive_out)
    {
        return false;
    }

    return true;
}

bool socks5clientStartUdpAssociation(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, bool *line_alive_out)
{
    *line_alive_out = true;
    lineRef(l);

    line_t                *control_l  = createInternalLine(t, l, kSocks5ClientLineKindUdpControl);
    socks5client_lstate_t *control_ls = lineGetState(control_l, t);

    addresscontextCopy(&control_ls->target_addr, &ls->target_addr);
    control_ls->protocol = ls->protocol;
    setLineProtocol(control_l, IP_PROTO_TCP);

    ls->control_line = control_l;

    if (! lineCallWithRef(control_l, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(l))
        {
            ls->control_line = NULL;
        }
        *line_alive_out = lineIsAlive(l);
        lineUnref(l);
        return false;
    }

    *line_alive_out = lineIsAlive(l);
    if (! *line_alive_out)
    {
        socks5clientCloseOwnedLine(t, control_l);
    }
    lineUnref(l);

    return true;
}

bool socks5clientForwardUdpApplicationPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf)
{
    buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    if (ls->phase == kSocks5ClientPhaseEstablished && ! ls->draining_up && bufferqueueGetBufCount(&ls->pending_up) == 0)
        return socks5clientForwardUdpPayloadToRelay(t, l, ls, buf);
    return socks5clientQueuePayload(t, l, buf) && socks5clientDrainPending(t, l);
}

bool socks5clientHandleUdpRelayPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf)
{
    line_t *application_l = ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    buf                = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    const uint8_t *raw = sbufGetRawPtr(buf);
    size_t         len = sbufGetLength(buf);

    if (len < 4 || raw[0] != 0 || raw[1] != 0)
    {
        lineReuseBuffer(l, buf);
        socks5clientCloseLineBidirectional(t, l);
        return false;
    }

    if (raw[2] != 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    address_context_t source   = {0};
    size_t            addr_len = 0;
    int               parsed   = socks5clientParseAddressBytes(raw + 3, len - 3, &source, &addr_len);

    if (parsed <= 0 || len < (size_t) (3 + addr_len))
    {
        addresscontextReset(&source);
        lineReuseBuffer(l, buf);
        if (parsed < 0)
        {
            socks5clientCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    addresscontextReset(&source);
    sbufShiftRight(buf, (uint32_t) (3 + addr_len));
    return lineCallWithRefWithBuf(application_l, tunnelPrevDownStreamPayload, t, buf);
}

void socks5clientOnUdpRelayEstablished(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    discard l;

    line_t *application_l = ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        return;
    }

    socks5client_lstate_t *application_ls = lineGetState(application_l, t);
    application_ls->udp_relay_ready       = true;
    discard socks5clientTryEstablishUdpApplication(t, application_l, application_ls);
}
