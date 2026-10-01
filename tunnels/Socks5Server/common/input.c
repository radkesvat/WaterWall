#include "internal.h"

#include "loggers/network_logger.h"

static bool socks5serverSendReplyAndClose(tunnel_t *t, line_t *l, uint8_t rep)
{
    socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, rep, NULL);
    return false;
}

/* Extract only metadata; never merge a fragmented prefix with its opaque tail. */
static sbuf_t *socks5serverReadControlPrefix(line_t *l, socks5server_lstate_t *ls, size_t length)
{
    assert(length <= kSocks5ServerMaxHandshakeBytes);
    sbuf_t *prefix = socks5serverAllocBuffer(l, (uint32_t) length);
    sbufSetLength(prefix, 0);
    bufferstreamMoveExactBytesTo(&ls->in_stream, prefix, length);
    return prefix;
}

static bool socks5serverParseControlInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        if (ls->phase == kSocks5ServerPhaseWaitMethod)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t head[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5Version)
            {
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            size_t total = (size_t) 2 + head[1];
            if (bufferstreamGetBufLen(&ls->in_stream) < total)
            {
                return true;
            }

            sbuf_t        *method_buf      = socks5serverReadControlPrefix(l, ls, total);
            const uint8_t *methods         = sbufGetRawPtr(method_buf);
            bool           offers_noauth   = false;
            bool           offers_userpass = false;

            for (uint8_t i = 0; i < head[1]; ++i)
            {
                offers_noauth |= methods[2 + i] == kSocks5NoAuthMethod;
                offers_userpass |= methods[2 + i] == kSocks5UserPassMethod;
            }
            lineReuseBuffer(l, method_buf);

            uint8_t selected = kSocks5NoAcceptable;
            if (ts->no_auth && offers_noauth)
            {
                selected = kSocks5NoAuthMethod;
            }
            else if (! ts->no_auth && offers_userpass)
            {
                selected = kSocks5UserPassMethod;
            }

            sbuf_t *reply = socks5serverCreateMethodReply(l, selected);
            if (selected == kSocks5NoAcceptable)
            {
                socks5serverLogAuthRejected(
                    t, l, NULL, 0, ts->no_auth ? "no-auth method not offered" : "username-password method not offered");
                socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, -1, reply);
                return false;
            }
            ls->phase = selected == kSocks5NoAuthMethod ? kSocks5ServerPhaseWaitRequest : kSocks5ServerPhaseWaitAuth;
            if (selected == kSocks5NoAuthMethod)
            {
                ls->user_handle = userHandleEmpty();
                socks5serverRecordLineUser(l, ls, &ls->user_handle);
            }
            if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
                return false;
            continue;
        }

        if (ls->phase == kSocks5ServerPhaseWaitAuth)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t head[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5AuthVersion)
            {
                socks5serverLogAuthRejected(t, l, NULL, 0, "invalid username-password auth version");
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }

            size_t required = (size_t) 2 + head[1] + 1;
            if (bufferstreamGetBufLen(&ls->in_stream) < required)
            {
                return true;
            }

            uint8_t plen = bufferstreamViewByteAt(&ls->in_stream, 2 + head[1]);
            required += plen;
            if (bufferstreamGetBufLen(&ls->in_stream) < required)
            {
                return true;
            }

            sbuf_t        *auth_buf    = socks5serverReadControlPrefix(l, ls, required);
            const uint8_t *raw         = sbufGetRawPtr(auth_buf);
            user_handle_t  user_handle = userHandleEmpty();
            bool           authenticated =
                socks5serverAuthUserFromClient(t, l, raw + 2, head[1], raw + 3 + head[1], plen, &user_handle);
            if (authenticated && ! socks5serverStoreAuthCredentials(ls, raw + 2, head[1], raw + 3 + head[1], plen))
            {
                socks5serverLogAuthRejected(t, l, raw + 2, head[1], "failed to retain authenticated credentials");
                authenticated = false;
            }
            lineReuseBuffer(l, auth_buf);

            sbuf_t *reply = socks5serverCreateAuthReply(l, authenticated ? 0x00 : 0x01);
            if (! authenticated)
            {
                socks5serverCloseControlLine(t, l, kSocks5ServerCloseInternal, -1, reply);
                return false;
            }
            ls->user_handle = user_handle;
            ls->phase       = kSocks5ServerPhaseWaitRequest;
            socks5serverRecordLineUser(l, ls, &ls->user_handle);
            if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, reply))
                return false;
            continue;
        }

        if (ls->phase == kSocks5ServerPhaseWaitRequest)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 4)
            {
                return true;
            }

            uint8_t head[4];
            bufferstreamViewBytesAt(&ls->in_stream, 0, head, sizeof(head));
            if (head[0] != kSocks5Version || head[2] != 0)
            {
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
            }

            uint8_t           request_buf[sizeof(head) + 1 + 16 + 2 + UINT8_MAX] = {0};
            size_t            available = bufferstreamGetBufLen(&ls->in_stream);
            size_t            copy_len  = min((size_t) sizeof(request_buf), available);
            address_context_t target    = {0};
            size_t            consumed  = 0;

            bufferstreamViewBytesAt(&ls->in_stream, 0, request_buf, copy_len);
            socks5_address_result_t parse_res =
                socks5serverParseAddressBytes(request_buf + 3, copy_len - 3, &target, &consumed);
            if (parse_res == kSocks5AddressNeedMore)
            {
                return true;
            }

            if (parse_res == kSocks5AddressInvalid)
            {
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyAddrNotSupported);
            }

            lineReuseBuffer(l, socks5serverReadControlPrefix(l, ls, 3 + consumed));

            if (head[1] == kSocks5CommandBind)
            {
                addresscontextReset(&target);
                return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
            }

            if (head[1] == kSocks5CommandConnect)
            {
                if (! ts->allow_connect)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
                }
                if (! addresscontextHasPort(&target))
                {
                    if (ts->verbose)
                    {
                        LOGW("Socks5Server: rejected CONNECT request with zero destination port");
                    }
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyAddrNotSupported);
                }

                socks5serverApplyDestinationContext(l, &target, false);
                addresscontextReset(&target);
                ls->phase             = kSocks5ServerPhaseConnectWaitEst;
                ls->next_initializing = true;
                ls->next_initialized  = true;
                if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
                {
                    return false;
                }
                ls->next_initializing = false;
                if (ls->prev_paused && ! ls->next_read_paused)
                {
                    ls->next_read_paused = true;
                    if (UNLIKELY(! lineCallWithRef(l, tunnelNextUpStreamPause, t)))
                        return false;
                }
                return socks5serverDrainControl(t, l);
            }

            if (head[1] == kSocks5CommandUdpAssoc)
            {
                address_context_t bind_ctx      = {0};
                uint16_t          assigned_port = 0;

                if (! ts->allow_udp)
                {
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
                }

                linePreferOrdinaryReadBoth(l);
                if (! socks5serverRegisterUdpAssociation(t, l, &ls->user_handle, &target, &assigned_port))
                {
                    LOGW("Socks5Server: failed to create a dynamic UDP association");
                    addresscontextReset(&target);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
                }

                LOGD("Socks5Server: opened dynamic UDP association endpoint on worker %u port %u",
                     (unsigned int) lineGetWID(l),
                     (unsigned int) assigned_port);

                addresscontextSetIpPort(&bind_ctx, &ts->udp_reply_ip, assigned_port);
                sbuf_t *reply = socks5serverCreateCommandReply(l, kSocks5ReplySucceeded, &bind_ctx);
                addresscontextReset(&bind_ctx);
                addresscontextReset(&target);
                if (reply == NULL)
                {
                    socks5serverUnregisterUdpAssociation(t, ls);
                    return socks5serverSendReplyAndClose(t, l, kSocks5ReplyGeneralFailure);
                }
                ls->phase              = kSocks5ServerPhaseUdpControl;
                ls->connect_reply_sent = true;
                bufferstreamEmpty(&ls->in_stream);
                bufferqueueDestroy(&ls->pending_up);
                return lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, reply);
            }

            addresscontextReset(&target);
            return socks5serverSendReplyAndClose(t, l, kSocks5ReplyCmdNotSupported);
        }

        return true;
    }
}

/* One parser owner; nested input follows the active input in the upstream FIFO. */
bool socks5serverControlDrainInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls)
{
    assert(! ls->input_draining);
    ls->input_draining = true;
    for (;;)
    {
        if (! socks5serverParseControlInput(t, l, ls))
            return false;
        if (ls->phase == kSocks5ServerPhaseUdpControl)
            break;
        if (ls->phase == kSocks5ServerPhaseConnectWaitEst || ls->phase == kSocks5ServerPhaseTcpEstablished)
        {
            if (ls->next_paused && (bufferstreamGetBufLen(&ls->in_stream) > kSocks5ServerMaxPendingBytes ||
                                    bufferqueueGetBufLen(&ls->pending_up) >
                                        kSocks5ServerMaxPendingBytes - bufferstreamGetBufLen(&ls->in_stream)))
            {
                socks5serverCloseControlLineBidirectional(t, l);
                return false;
            }
            ls->input_draining = false;
            return socks5serverDrainControl(t, l);
        }
        if (bufferstreamGetBufLen(&ls->in_stream) > kSocks5ServerMaxHandshakeBytes)
        {
            socks5serverCloseControlLineBidirectional(t, l);
            return false;
        }
        sbuf_t *queued = bufferqueuePopFront(&ls->pending_up);
        if (queued == NULL)
            break;
        bufferstreamPush(&ls->in_stream, queued);
    }
    ls->input_draining = false;
    return true;
}
