#include "internal.h"

#include "loggers/network_logger.h"

static int getCommandReplyLength(buffer_stream_t *stream)
{
    size_t available = bufferstreamGetBufLen(stream);
    if (available < 4)
    {
        return 0;
    }

    uint8_t header[5] = {0};
    size_t  peek_len  = min(available, sizeof(header));
    bufferstreamViewBytesAt(stream, 0, header, peek_len);

    switch (header[3])
    {
    case kSocks5AddrTypeIpv4:
        return available >= 10 ? 10 : 0;

    case kSocks5AddrTypeIpv6:
        return available >= 22 ? 22 : 0;

    case kSocks5AddrTypeDomain: {
        if (available < 5)
        {
            return 0;
        }

        size_t total = (size_t) 7 + (size_t) header[4];
        return available >= total ? (int) total : 0;
    }

    default:
        return -1;
    }
}

/* Consume metadata only; fragmented replies must not merge the opaque body. */
static sbuf_t *readHandshakePrefix(line_t *l, socks5client_lstate_t *ls, size_t length)
{
    assert(length <= kSocks5ClientMaxHandshakeBytes);
    sbuf_t *prefix = socks5clientAllocHandshakeBuffer(l, (uint32_t) length);
    sbufSetLength(prefix, 0);
    bufferstreamMoveExactBytesTo(&ls->in_stream, prefix, length);
    return prefix;
}

static bool parseHandshakeInput(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        if (ls->phase == kSocks5ClientPhaseEstablished)
        {
            return true;
        }

        if (ls->phase == kSocks5ClientPhaseWaitMethod)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t reply[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, reply, sizeof(reply));
            lineReuseBuffer(l, readHandshakePrefix(l, ls, sizeof(reply)));

            if (reply[0] != kSocks5Version)
            {
                LOGE("Socks5Client: invalid method reply version 0x%02x", reply[0]);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] == kSocks5NoAcceptable)
            {
                LOGE("Socks5Client: proxy rejected all advertised authentication methods");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] == kSocks5NoAuthMethod)
            {
                if (! socks5clientSendConnectRequest(t, l, ls))
                {
                    return false;
                }
                continue;
            }

            if (reply[1] == kSocks5UserPassMethod)
            {
                if (ts->username_len == 0 || ts->password_len == 0)
                {
                    LOGE("Socks5Client: proxy requested username/password authentication but no credentials are "
                         "configured");
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                if (! socks5clientSendAuthRequest(t, l, ls))
                {
                    return false;
                }
                continue;
            }

            LOGE("Socks5Client: proxy selected unsupported auth method 0x%02x", reply[1]);
            socks5clientCloseLineBidirectional(t, l);
            return false;
        }

        if (ls->phase == kSocks5ClientPhaseWaitAuth)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t reply[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, reply, sizeof(reply));
            lineReuseBuffer(l, readHandshakePrefix(l, ls, sizeof(reply)));

            if (reply[0] != kSocks5AuthVersion || reply[1] != 0x00)
            {
                LOGE("Socks5Client: proxy authentication failed");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (! socks5clientSendConnectRequest(t, l, ls))
            {
                return false;
            }
            continue;
        }

        if (ls->phase == kSocks5ClientPhaseWaitCommand)
        {
            int reply_len = getCommandReplyLength(&ls->in_stream);
            if (reply_len == 0)
            {
                return true;
            }

            if (reply_len < 0)
            {
                LOGE("Socks5Client: proxy sent an invalid command reply");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            sbuf_t        *reply_buf = readHandshakePrefix(l, ls, (size_t) reply_len);
            const uint8_t *reply     = sbufGetRawPtr(reply_buf);

            if (reply[0] != kSocks5Version)
            {
                LOGE("Socks5Client: invalid command reply version 0x%02x", reply[0]);
                lineReuseBuffer(l, reply_buf);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] != 0x00)
            {
                LOGE("Socks5Client: proxy command failed with reply code 0x%02x", reply[1]);
                lineReuseBuffer(l, reply_buf);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (ls->protocol == kSocks5ClientProtocolUdp)
            {
                address_context_t relay_addr = {0};
                size_t            consumed   = 0;
                int parsed = socks5clientParseAddressBytes(reply + 3, (size_t) reply_len - 3, &relay_addr, &consumed);
                lineReuseBuffer(l, reply_buf);

                if (parsed <= 0)
                {
                    addresscontextReset(&relay_addr);
                    LOGE("Socks5Client: proxy sent an invalid UDP relay address");
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                addresscontextSetOnlyProtocol(&relay_addr, IP_PROTO_UDP);
                addresscontextCopy(&ls->relay_addr, &relay_addr);
                ls->phase = kSocks5ClientPhaseEstablished;

                bool control_alive = true;
                if (! socks5clientStartUdpRelayLine(t, l, ls, &relay_addr, &control_alive))
                {
                    addresscontextReset(&relay_addr);
                    if (! control_alive)
                    {
                        return false;
                    }
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                line_t *application_l = ls->application_line;
                addresscontextReset(&relay_addr);
                if (application_l == NULL || ! lineIsAlive(application_l))
                {
                    return false;
                }

                socks5client_lstate_t *application_ls = lineGetState(application_l, t);
                application_ls->udp_control_ready     = true;

                if (ts->verbose)
                {
                    LOGD("Socks5Client: SOCKS5 UDP association completed");
                }

                return socks5clientTryEstablishUdpApplication(t, application_l, application_ls);
            }

            lineReuseBuffer(l, reply_buf);
            ls->phase = kSocks5ClientPhaseEstablished;
            return true;
        }

        return true;
    }
}

bool socks5clientQueueReplyInput(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls      = lineGetState(l, t);
    const size_t           length  = sbufGetLength(buf);
    const size_t           active  = bufferstreamGetBufLen(&ls->in_stream);
    const size_t           entries = (size_t) bs_doublequeue_t_size(&ls->in_stream.q);
    if (length > kSocks5ClientMaxPendingDownBytes || active > kSocks5ClientMaxPendingDownBytes - length ||
        bufferqueueGetBufLen(&ls->pending_down) > kSocks5ClientMaxPendingDownBytes - length - active ||
        entries >= kSocks5ClientMaxPendingBuffers ||
        bufferqueueGetBufCount(&ls->pending_down) >= kSocks5ClientMaxPendingBuffers - entries ||
        ! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        lineReuseBuffer(l, buf);
        socks5clientCloseLineBidirectional(t, l);
        return false;
    }
    return true;
}

bool socks5clientDrainHandshakeInput(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    if (ls->input_draining)
        return true;
    ls->input_draining = true;
    for (;;)
    {
        if (! parseHandshakeInput(t, l, ls))
            return false;
        if (ls->phase == kSocks5ClientPhaseEstablished)
            break;
        if (bufferstreamGetBufLen(&ls->in_stream) > kSocks5ClientMaxHandshakeBytes)
        {
            socks5clientCloseLineBidirectional(t, l);
            return false;
        }
        sbuf_t *queued = bufferqueuePopFront(&ls->pending_down);
        if (queued == NULL)
        {
            ls->input_draining = false;
            return true;
        }
        bufferstreamPush(&ls->in_stream, queued);
    }
    if (ls->kind == kSocks5ClientLineKindUdpControl)
    {
        bufferstreamEmpty(&ls->in_stream);
        bufferqueueDestroy(&ls->pending_down);
        ls->input_draining = false;
        return true;
    }

    /* Finish the accepted reply's opaque tail. Reentrant deliveries stay behind
     * it; only the subsequent retained backlog waits for receive permission. */
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *tail = bufferstreamIdealRead(&ls->in_stream);
        if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, tail))
            return false;
    }
    while (! ls->prev_paused && bufferqueueGetBufCount(&ls->pending_down) != 0)
    {
        sbuf_t *tail = bufferqueuePopFront(&ls->pending_down);
        if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, tail))
            return false;
    }
    ls->input_draining = false;
    if (ls->prev_paused && ! ls->read_pause_sent)
    {
        ls->read_pause_sent = true;
        if (! lineCallWithRef(l, tunnelNextUpStreamPause, t))
            return false;
    }
    return socks5clientDrainPending(t, l);
}
