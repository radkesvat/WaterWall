#include "rtmp_tunnel.h"

#include "loggers/network_logger.h"

typedef struct rtmp_tstate_s
{
    rtmp_settings_t      settings;
    const rtmp_output_t *output;
    rtmp_role_t          role;
} rtmp_tstate_t;

typedef enum rtmp_deadline_e
{
    kRtmpNoDeadline,
    kRtmpSetupDeadline,
    kRtmpSendDeadline
} rtmp_deadline_t;

typedef struct rtmp_lstate_s
{
    rtmp_session_t     *session;
    line_t             *line;
    tunnel_t           *tunnel;
    wloop_t            *loop;
    wtimer_t           *timer;
    uint64_t            started_us;
    uint64_t            deadline_us;
    rtmp_deadline_t     deadline : 8;
    rtmp_close_origin_t draining_from : 8;
    bool                pumping : 1;
    bool                client_started : 1;
    bool                next_admitted : 1;
    bool                deferred_carrier_pause : 1;
    bool                app_received_pause : 1;
    bool                app_pause_sent : 1;
    bool                app_consumer_paused : 1;
    bool                receive_high : 1;
    bool                carrier_pause_sent : 1;
    bool                reading_for_credit : 1;
} rtmp_lstate_t;

static void rtmpCancelDeadline(rtmp_lstate_t *ls)
{
    wtimer_t *timer = ls->timer;
    ls->timer       = NULL;
    ls->deadline    = kRtmpNoDeadline;
    ls->deadline_us = 0;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

static void rtmpClose(tunnel_t *t, line_t *l, rtmp_close_origin_t origin)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    const bool     finish_next =
        origin != kRtmpCloseFromNext && ls->draining_from != kRtmpCloseFromNext && ls->next_admitted;
    const bool finish_prev = origin != kRtmpCloseFromPrev && ls->draining_from != kRtmpCloseFromPrev;

    lineRef(l);
    rtmpCancelDeadline(ls);
    if (ls->session != NULL)
    {
        rtmpSessionDestroy(ls->session);
    }
    memoryZero(ls, sizeof(*ls));

    if (finish_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (finish_prev && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnref(l);
}

static void rtmpFail(tunnel_t *t, line_t *l, const char *reason)
{
    LOGW("%s: %s", tunnelGetNode(t)->type, reason);
    rtmpClose(t, l, kRtmpCloseLocal);
}

static void rtmpDeadlineExpired(wtimer_t *timer)
{
    rtmp_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->timer == timer && ls->session != NULL);

    /* The event loop releases the executing one-shot. */
    ls->timer = NULL;
    rtmpFail(ls->tunnel,
             ls->line,
             ls->deadline == kRtmpSetupDeadline ? "session setup timed out" : "application output stalled");
}

static bool rtmpSetDeadline(rtmp_lstate_t *ls, rtmp_deadline_t deadline, uint32_t delay_ms)
{
    const uint64_t now = getHRTimeUs();
    if (ls->timer == NULL)
    {
        ls->timer = wtimerAddDeadline(ls->loop, rtmpDeadlineExpired, delay_ms);
        if (ls->timer == NULL)
        {
            return false;
        }
        weventSetUserData(ls->timer, ls);
    }
    else if (! wtimerReset(ls->timer, delay_ms))
    {
        return false;
    }
    ls->deadline    = deadline;
    ls->deadline_us = now + (uint64_t) delay_ms * 1000U;
    return true;
}

static bool rtmpRefreshSendDeadline(rtmp_lstate_t *ls, const rtmp_tstate_t *ts)
{
    if (ls->deadline == kRtmpSendDeadline)
    {
        if (rtmpSessionHasTxTail(ls->session))
        {
            return rtmpSetDeadline(ls, kRtmpSendDeadline, ts->settings.send_timeout_ms);
        }
        rtmpCancelDeadline(ls);
    }
    return true;
}

/* Dispatch callers retain the exact line while checking this predicate. */
static bool rtmpLineIsLive(const rtmp_lstate_t *ls, line_t *l)
{
    return lineIsAlive(l) && ls->session != NULL;
}

static bool rtmpPublishAppPressure(tunnel_t *t, line_t *l, rtmp_lstate_t *ls, const rtmp_tstate_t *ts)
{
    if (ts->role == kRtmpServerRole && ! ls->next_admitted)
    {
        return true;
    }
    const bool received = ls->app_received_pause && ! ls->deferred_carrier_pause;
    const bool paused   = received || rtmpSessionHasTxTail(ls->session);
    if (ls->app_pause_sent == paused)
    {
        return true;
    }
    ls->app_pause_sent = paused;
    ts->output->application_pressure(t, l, paused);
    return rtmpLineIsLive(ls, l);
}

static bool rtmpPublishCarrierPressure(tunnel_t *t, line_t *l, rtmp_lstate_t *ls, const rtmp_tstate_t *ts)
{
    const size_t pending = rtmpSessionPendingRx(ls->session);
    ls->receive_high     = ls->receive_high ? pending > RTMP_SESSION_LOW_WATER : pending >= RTMP_SESSION_HIGH_WATER;

    /* Reopen a paused carrier only when an encoded chunk actually needs an
     * ACK. Keep it readable through that tail, including between ACKs. */
    if (rtmpSessionNeedsSendCredit(ls->session))
        ls->reading_for_credit = true;
    else if (! rtmpSessionHasTxTail(ls->session))
        ls->reading_for_credit = false;
    const bool paused =
        (ls->receive_high || ls->app_consumer_paused) && rtmpSessionIsActive(ls->session) && ! ls->reading_for_credit;
    if (ls->carrier_pause_sent == paused)
    {
        return true;
    }
    ls->carrier_pause_sent = paused;
    ts->output->carrier_pressure(t, l, paused);
    return rtmpLineIsLive(ls, l);
}

static bool rtmpSend(tunnel_t *t, line_t *l, rtmp_lstate_t *ls, const rtmp_tstate_t *ts, bool wire, size_t length)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = bufferpoolTryGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    if (buf == NULL)
    {
        rtmpFail(t, l, "output buffer geometry refused");
        return false;
    }
    bool         sent_application_data = false;
    const size_t taken = wire ? rtmpSessionTakeWire(ls->session, sbufGetMutablePtr(buf), length, &sent_application_data)
                              : rtmpSessionTakePlain(ls->session, sbufGetMutablePtr(buf), length);
    if (taken != length)
    {
        LOGF("%s: queued output length changed without dispatch", tunnelGetNode(t)->type);
        abortProgramNow(1);
    }
    sbufSetLength(buf, taken);

    if (sent_application_data && ! rtmpRefreshSendDeadline(ls, ts))
    {
        bufferpoolReuseBuffer(pool, buf);
        rtmpFail(t, l, "could not refresh the application output deadline");
        return false;
    }
    if (wire)
        ts->output->wire_payload(t, l, buf);
    else
        ts->output->application_payload(t, l, buf);
    return rtmpLineIsLive(ls, l);
}

/* Complete the already-decoded FIFO before notifying the surviving application.
 * A nested Finish may retire the session during any handoff. */
static void rtmpFinishDecoded(tunnel_t *t, line_t *l, rtmp_close_origin_t origin)
{
    rtmp_lstate_t       *ls = lineGetState(l, t);
    const rtmp_tstate_t *ts = tunnelGetState(t);
    lineRef(l);
    ls->draining_from = origin;
    rtmpCancelDeadline(ls);
    size_t length;
    while (wloopNormalDispatchAllowed(ls->loop) && (length = rtmpSessionPeekPlain(ls->session)) != 0)
    {
        if (! rtmpSend(t, l, ls, ts, false, length))
        {
            lineUnref(l);
            return;
        }
    }
    rtmpClose(t, l, origin);
    lineUnref(l);
}

static void rtmpPump(tunnel_t *t, line_t *l, rtmp_lstate_t *ls)
{
    const rtmp_tstate_t *ts = tunnelGetState(t);
    if (ls->pumping)
    {
        /* A nested application payload may return while the outer callback
         * still owns the pump. Publish its producer hold before it returns. */
        lineRef(l);
        discard rtmpPublishAppPressure(t, l, ls, ts);
        lineUnref(l);
        return;
    }

    lineRef(l);
    ls->pumping = true;
    while (wloopNormalDispatchAllowed(ls->loop))
    {
        if (rtmpSessionPeerClosed(ls->session))
        {
            rtmpFinishDecoded(t, l, kRtmpCloseLocal);
            goto done;
        }
        const uint64_t now = getHRTimeUs();
        if (ls->deadline != kRtmpNoDeadline && now >= ls->deadline_us)
        {
            rtmpFail(
                t, l, ls->deadline == kRtmpSetupDeadline ? "session setup timed out" : "application output stalled");
            goto done;
        }
        if (ls->deadline == kRtmpSetupDeadline && rtmpSessionIsActive(ls->session))
        {
            rtmpCancelDeadline(ls);
        }
        if (! rtmpPublishAppPressure(t, l, ls, ts) || ! rtmpPublishCarrierPressure(t, l, ls, ts))
        {
            goto done;
        }
        if (! wloopNormalDispatchAllowed(ls->loop))
        {
            break;
        }

        if (ts->role == kRtmpClientRole && ! ls->client_started)
        {
            ls->client_started = true;
            if (! rtmpSessionStart(ls->session))
            {
                rtmpFail(t, l, "could not start the RTMP handshake");
                goto done;
            }
            continue;
        }
        if (rtmpSessionPublishPending(ls->session))
        {
            if (! ls->next_admitted)
            {
                ls->next_admitted = true;
                tunnelNextUpStreamInit(t, l);
                if (! rtmpLineIsLive(ls, l))
                {
                    goto done;
                }
                ls->deferred_carrier_pause = false;
                continue;
            }
            /* Init admits payload. The next node may need those bytes to establish its own transport. */
            if (! rtmpSessionAccept(ls->session))
            {
                rtmpFail(t, l, "could not queue publication acceptance");
                goto done;
            }
            continue;
        }

        const size_t wire = rtmpSessionPeekWire(ls->session);
        if (wire != 0)
        {
            if (! rtmpSend(t, l, ls, ts, true, wire))
            {
                goto done;
            }
            continue;
        }

        /* Continue parsing control traffic while retaining the consumer's
         * decoded bytes in the bounded receive queue until it resumes. */
        const size_t plain = ls->app_consumer_paused ? 0 : rtmpSessionPeekPlain(ls->session);
        if (plain != 0)
        {
            if (! rtmpSend(t, l, ls, ts, false, plain))
            {
                goto done;
            }
            continue;
        }

        bool progress = false;
        if (! rtmpSessionStep(ls->session, (uint32_t) ((now - ls->started_us) / 1000U), &progress))
        {
            rtmpFail(t, l, "RTMP protocol or session limit failure");
            goto done;
        }
        if (! progress)
        {
            if (ls->deadline == kRtmpNoDeadline && rtmpSessionIsActive(ls->session) &&
                rtmpSessionHasTxTail(ls->session) &&
                ! rtmpSetDeadline(ls, kRtmpSendDeadline, ts->settings.send_timeout_ms))
            {
                rtmpFail(t, l, "could not arm the application output deadline");
                goto done;
            }
            break;
        }
    }
    ls->pumping = false;
done:
    lineUnref(l);
}

bool rtmpInitLine(tunnel_t *t, line_t *l)
{
    const rtmp_tstate_t   *ts       = tunnelGetState(t);
    const rtmp_settings_t *settings = &ts->settings;
    rtmp_lstate_t         *ls       = lineGetState(l, t);
    assert(! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    assert(lineIsOnCurrentWorker(l));

    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return false;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    *ls = (rtmp_lstate_t) {.line = l, .tunnel = t, .loop = getWorkerLoop(lineGetWID(l)), .started_us = getHRTimeUs()};
    if (! wloopNormalDispatchAllowed(ls->loop))
    {
        rtmpClose(t, l, kRtmpCloseLocal);
        return false;
    }
    ls->session = rtmpSessionCreate(
        ts->role == kRtmpServerRole, settings->app, settings->stream, settings->tc_url, settings->block_size);
    if (ls->session == NULL || ! rtmpSetDeadline(ls, kRtmpSetupDeadline, settings->setup_timeout_ms))
    {
        rtmpFail(t, l, "could not initialize the RTMP session");
        return false;
    }
    return true;
}

void rtmpStartCarrier(tunnel_t *t, line_t *l)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    lineRef(l);
    ls->pumping       = true;
    ls->next_admitted = true;
    tunnelNextUpStreamInit(t, l);
    if (rtmpLineIsLive(ls, l))
    {
        ls->pumping = false;
        rtmpPump(t, l, ls);
    }
    lineUnref(l);
}

void rtmpNextEstablished(tunnel_t *t, line_t *l)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (ls->session == NULL || ls->draining_from != kRtmpOpen)
    {
        return;
    }
    assert(ls->next_admitted);

    tunnelPrevDownStreamEst(t, l);
}

static bool rtmpCanAcceptInput(const rtmp_lstate_t *ls)
{
    return ls->session != NULL && ls->draining_from == kRtmpOpen && wloopNormalDispatchAllowed(ls->loop);
}

static bool rtmpAdmitPayload(line_t *l, const rtmp_lstate_t *ls, sbuf_t *buf)
{
    if (! rtmpCanAcceptInput(ls))
    {
        lineReuseBuffer(l, buf);
        return false;
    }
    return true;
}

typedef bool (*rtmp_queue_input_fn)(rtmp_session_t *session, const uint8_t *bytes, size_t length);

static void rtmpQueuePayload(tunnel_t *t, line_t *l, rtmp_lstate_t *ls, sbuf_t *buf, rtmp_queue_input_fn enqueue)
{
    if (sbufIsSplice(buf))
    {
        lineReuseBuffer(l, buf);
        rtmpFail(t, l, "received a nonresident buffer");
        return;
    }
    const bool queued = enqueue(ls->session, sbufGetRawPtr(buf), sbufGetLength(buf));
    lineReuseBuffer(l, buf);
    if (! queued)
    {
        rtmpFail(t, l, "pending stream input exceeded its limit");
        return;
    }
    rtmpPump(t, l, ls);
}

void rtmpSubmitApplication(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (! rtmpAdmitPayload(l, ls, buf))
        return;
    assert(((const rtmp_tstate_t *) tunnelGetState(t))->role == kRtmpClientRole || ls->next_admitted);
    rtmpQueuePayload(t, l, ls, buf, rtmpSessionQueuePlain);
}

void rtmpSubmitCarrier(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (! rtmpAdmitPayload(l, ls, buf))
        return;
    assert(((const rtmp_tstate_t *) tunnelGetState(t))->role == kRtmpServerRole || ls->next_admitted);
    rtmpQueuePayload(t, l, ls, buf, rtmpSessionQueueCarrier);
}

void rtmpSetApplicationPaused(tunnel_t *t, line_t *l, bool paused)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (! rtmpCanAcceptInput(ls))
        return;
    ls->app_consumer_paused = paused;
    rtmpPump(t, l, ls);
}

void rtmpSetCarrierPaused(tunnel_t *t, line_t *l, bool paused)
{
    const rtmp_tstate_t *ts = tunnelGetState(t);
    rtmp_lstate_t       *ls = lineGetState(l, t);
    if (! rtmpCanAcceptInput(ls))
        return;
    ls->app_received_pause     = paused;
    ls->deferred_carrier_pause = ts->role == kRtmpServerRole && paused && ! ls->next_admitted;
    rtmpPump(t, l, ls);
}

void rtmpApplicationFinish(tunnel_t *t, line_t *l, rtmp_close_origin_t origin)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (ls->session == NULL)
        return;
    assert(origin != kRtmpCloseFromNext || ls->next_admitted);
    rtmpClose(t, l, origin);
}

void rtmpCarrierFinish(tunnel_t *t, line_t *l, rtmp_close_origin_t origin)
{
    rtmp_lstate_t *ls = lineGetState(l, t);
    if (ls->session == NULL)
        return;
    assert(origin != kRtmpCloseFromNext || ls->next_admitted);
    if (ls->draining_from == kRtmpOpen && rtmpSessionPeekPlain(ls->session) != 0)
    {
        rtmpFinishDecoded(t, l, origin);
        return;
    }
    rtmpClose(t, l, origin);
}

tunnel_t *rtmpTunnelCreate(node_t *node, const rtmp_settings_t *settings, rtmp_role_t role, const rtmp_output_t *output)
{
    assert(node != NULL && settings != NULL && output != NULL);
    tunnel_t *t = tunnelCreate(node, sizeof(rtmp_tstate_t), sizeof(rtmp_lstate_t));
    if (t != NULL)
    {
        rtmp_tstate_t *ts = tunnelGetState(t);
        *ts               = (rtmp_tstate_t) {.settings = *settings, .role = role, .output = output};
    }
    return t;
}
