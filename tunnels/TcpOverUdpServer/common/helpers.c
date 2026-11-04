#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverRetireService(tcpoverudpserver_session_t *session, bool notify_service)
{
    line_t *service = session->service;
    if (service == NULL)
    {
        return;
    }
    tunnel_t *t      = session->carrier->tunnel;
    session->service = NULL;
    lineRef(service);
    tcpoverudpserverLinestateDestroy(lineGetState(service, t));
    if (notify_service && session->init_entered)
    {
        tunnelNextUpStreamFinish(t, service);
    }
    if (lineIsAlive(service))
    {
        lineDestroy(service);
    }
    lineUnref(service);
}

void tcpoverudpserverCarrierClose(tcpoverudpserver_carrier_t *carrier, bool notify_owner)
{
    if (! carrier->active)
    {
        return;
    }
    tcpoverudpserverCarrierRetain(carrier);
    carrier->active                   = false;
    carrier->pending                  = false;
    tunnel_t                  *t      = carrier->tunnel;
    line_t                    *line   = carrier->line;
    tcpoverudpserver_tstate_t *ts     = tunnelGetState(t);
    tcpoverudpserver_worker_t *worker = &ts->workers[carrier->wid];
    if (carrier->prev != NULL)
    {
        carrier->prev->next = carrier->next;
    }
    else
    {
        assert(worker->carriers == carrier);
        worker->carriers = carrier->next;
    }
    if (carrier->next != NULL)
    {
        carrier->next->prev = carrier->prev;
    }
    carrier->prev = carrier->next = NULL;
    if (carrier->pending_timer != NULL)
    {
        weventSetUserData(carrier->pending_timer, NULL);
        wtimerDelete(carrier->pending_timer);
        carrier->pending_timer = NULL;
    }
    bufferqueueDestroy(&carrier->input);
    bufferbudgetAssertEmpty(&carrier->input_budget);
    tcpoverudpserverLinestateDestroy(lineGetState(line, t));
    /* Close source admission before service Finish can reenter with another datagram.
     * This is a borrowed normal carrier; its UDP owner performs logical destruction.
     * The carrier's physical reference and saved pool outlive all session cleanup. */
    if (notify_owner && lineIsAlive(line))
    {
        tunnelPrevDownStreamFinish(t, line);
    }
    while (carrier->sessions != NULL)
    {
        touSessionAbort(carrier->sessions->engine, kTouAborted);
    }
    tcpoverudpserverCarrierRelease(carrier); // Published carrier/root ownership.
    tcpoverudpserverCarrierRelease(carrier); // Call-local guard.
}

static void sessionDestroyed(void *user)
{
    tcpoverudpserver_session_t *session = user;
    assert(session->service == NULL);
    tcpoverudpserverCarrierRelease(session->carrier);
    memoryFree(session);
}

static void sessionTerminal(void *user, tou_result_t result)
{
    tcpoverudpserver_session_t *session = user;
    tcpoverudpserver_carrier_t *carrier = session->carrier;
    if (session->prev != NULL)
    {
        session->prev->next = session->next;
    }
    else
    {
        assert(carrier->sessions == session);
        carrier->sessions = session->next;
    }
    if (session->next != NULL)
    {
        session->next->prev = session->prev;
    }
    session->prev = session->next = NULL;
    assert(carrier->session_count > 0);
    --carrier->session_count;
    tcpoverudpserverRetireService(session, true);
    if (result == kTouUnconfirmed)
    {
        LOGW("TcpOverUdpServer: close delivery unconfirmed at fixed deadline");
    }
    else if (result != kTouConfirmed && result != kTouPeerDrained && result != kTouAborted)
    {
        LOGD("TcpOverUdpServer: session aborted (result %d)", (int) result);
    }
    if (carrier->active && carrier->sessions == NULL && ! carrier->pending)
    {
        tcpoverudpserverCarrierClose(carrier, true);
    }
    touSessionRelease(session->engine); // Carrier session-map ownership.
}

static void sessionEmit(void *user, sbuf_t *packet)
{
    tcpoverudpserver_session_t *session = user;
    tcpoverudpserver_carrier_t *carrier = session->carrier;
    if (! carrier->active)
    {
        bufferpoolReuseBuffer(carrier->pool, packet);
        return;
    }
    line_t *line = carrier->line;
    lineRef(line);
    tunnelPrevDownStreamPayload(carrier->tunnel, line, packet);
    lineUnref(line);
}

static void sessionPayload(void *user, sbuf_t *payload)
{
    tcpoverudpserver_session_t *session = user;
    line_t                     *service = session->service;
    if (service == NULL || ! session->carrier->active)
    {
        bufferpoolReuseBuffer(session->carrier->pool, payload);
        return;
    }
    assert(session->init_entered);
    lineRef(service);
    tunnelNextUpStreamPayload(session->carrier->tunnel, service, payload);
    lineUnref(service);
}

static void sessionPeerClose(void *user)
{
    tcpoverudpserverRetireService(user, true);
}

static void sessionPressure(void *user, bool paused)
{
    tcpoverudpserver_session_t *session = user;
    line_t                     *service = session->service;
    if (service == NULL || ! session->init_entered || ! session->carrier->active)
    {
        return;
    }
    lineRef(service);
    if (paused)
    {
        tunnelNextUpStreamPause(session->carrier->tunnel, service);
    }
    else
    {
        tunnelNextUpStreamResume(session->carrier->tunnel, service);
    }
    lineUnref(service);
}

void tcpoverudpserverCarrierControl(tcpoverudpserver_carrier_t *carrier, uint8_t kind,
                                    const uint8_t client[kTouNonceSize], const uint8_t server[kTouNonceSize],
                                    const tou_settings_t *settings)
{
    assert(carrier->active);
    sbuf_t *packet = touControlCreate(lineGetBufferPool(carrier->line), kind, client, server, settings);
    if (packet == NULL)
    {
        tcpoverudpserverCarrierClose(carrier, true);
        return;
    }
    line_t *line = carrier->line;
    lineRef(line);
    tunnelPrevDownStreamPayload(carrier->tunnel, line, packet);
    lineUnref(line);
}

static tcpoverudpserver_session_t *findSession(tcpoverudpserver_carrier_t *carrier, const tou_wire_t *wire,
                                               bool exact_pair)
{
    for (tcpoverudpserver_session_t *session = carrier->sessions; session != NULL; session = session->next)
    {
        if (memcmp(touSessionClientNonce(session->engine), wire->client_nonce, kTouNonceSize) == 0 &&
            (! exact_pair || memcmp(touSessionServerNonce(session->engine), wire->server_nonce, kTouNonceSize) == 0))
        {
            return session;
        }
    }
    return NULL;
}

static void copyServiceContext(line_t *service, line_t *carrier)
{
    addresscontextCopy(lineGetSourceAddressContext(service), lineGetSourceAddressContext(carrier));
    addresscontextCopy(lineGetDestinationAddressContext(service), lineGetDestinationAddressContext(carrier));
    lineGetRoutingContext(service)->local_listener_port = lineGetRoutingContext(carrier)->local_listener_port;
    lineGetRoutingContext(service)->peer_source_port    = lineGetRoutingContext(carrier)->peer_source_port;
    lineCopyUsers(service, carrier);
    if (lineIsFallback(carrier))
    {
        lineMarkFallback(service);
        if (lineHasCloseLingerReason(carrier, kLineCloseLingerPeerWriteShutdown))
        {
            lineRequestCloseLinger(service, kLineCloseLingerPeerWriteShutdown);
        }
    }
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(service), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(service), IP_PROTO_TCP);
    if (linePrefersOrdinaryReadUpstream(carrier))
    {
        linePreferOrdinaryReadUpstream(service);
    }
    if (linePrefersOrdinaryReadDownstream(carrier))
    {
        linePreferOrdinaryReadDownstream(service);
    }
}

static void promoteSession(tcpoverudpserver_carrier_t *carrier)
{
    tcpoverudpserver_tstate_t *ts = tunnelGetState(carrier->tunnel);
    assert(carrier->active && carrier->pending && carrier->session_count < kTouMaximumSessions);
    tcpoverudpserver_session_t *session = memoryAllocateZero(sizeof(*session));
    session->carrier                    = carrier;
    session->offered_settings           = carrier->offered_settings;
    tcpoverudpserverCarrierRetain(carrier);
    tou_config_t config = {
        .send_mtu                  = ts->send_mtu,
        .fec_enabled               = ts->fec_enabled,
        .fec_data_shards           = ts->fec_data_shards,
        .fec_parity_shards         = ts->fec_parity_shards,
        .kcp_nodelay               = ts->kcp_nodelay,
        .kcp_no_congestion_control = ts->kcp_no_congestion_control,
        .kcp_interval_ms           = ts->kcp_interval_ms,
        .kcp_resend                = ts->kcp_resend,
        .kcp_send_window           = ts->kcp_send_window,
        .kcp_recv_window           = ts->kcp_recv_window,
        .kcp_initial_cwnd          = ts->kcp_initial_cwnd,
        .kcp_rx_minrto_ms          = ts->kcp_rx_minrto_ms,
        .kcp_send_buffer_limit     = ts->kcp_send_buffer_limit,
        .ping_interval_ms          = ts->ping_interval_ms,
        .no_recv_timeout_ms        = ts->no_recv_timeout_ms,
        .close_drain_timeout_ms    = ts->close_drain_timeout_ms,
        .pool                      = lineGetBufferPool(carrier->line),
        .loop                      = getWorkerLoop(lineGetWID(carrier->line)),
    };
    const tou_callbacks_t callbacks = {
        .emit         = sessionEmit,
        .payload      = sessionPayload,
        .peer_close   = sessionPeerClose,
        .pressure     = sessionPressure,
        .terminal     = sessionTerminal,
        .destroy_user = sessionDestroyed,
    };
    session->engine = touSessionCreate(
        &config, &callbacks, session, false, carrier->client_nonce, carrier->server_nonce, &carrier->pending_settings);
    if (session->engine == NULL)
    {
        tcpoverudpserverCarrierRelease(carrier);
        memoryFree(session);
        return;
    }
    line_t *service  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(carrier->tunnel)), lineGetWID(carrier->line));
    session->service = service;
    copyServiceContext(service, carrier->line);
    tcpoverudpserver_lstate_t *service_ls = lineGetState(service, carrier->tunnel);
    *service_ls =
        (tcpoverudpserver_lstate_t) {.kind = kTcpOverUdpServerService, .carrier = carrier, .session = session};
    session->next = carrier->sessions;
    if (session->next != NULL)
    {
        session->next->prev = session;
    }
    carrier->sessions = session;
    ++carrier->session_count;
    carrier->pending = false;
    weventSetUserData(carrier->pending_timer, NULL);
    wtimerDelete(carrier->pending_timer);
    carrier->pending_timer = NULL;
    /* READY can immediately return KCP data or close the carrier. The service exists, but its next side is unopened. */
    tou_session_t *engine = session->engine;
    touSessionRetain(engine);
    tcpoverudpserverCarrierControl(
        carrier, kTouReady, touSessionClientNonce(engine), touSessionServerNonce(engine), touSessionSettings(engine));
    if (touSessionIsAlive(engine) && session->service != NULL)
    {
        session->init_entered = true;
        lineRef(service);
        tunnelNextUpStreamInit(carrier->tunnel, service);
        bool attached = lineIsAlive(service) && session->service == service;
        lineUnref(service);
        if (touSessionIsAlive(engine))
        {
            if (attached && carrier->transport_paused && ! session->carrier_pause_delivered)
            {
                session->carrier_pause_delivered = true;
                lineRef(service);
                tunnelNextUpStreamPause(carrier->tunnel, service);
                attached = lineIsAlive(service) && session->service == service;
                lineUnref(service);
            }
            if (attached && carrier->transport_established)
            {
                lineRef(service);
                tunnelNextUpStreamEst(carrier->tunnel, service);
                lineUnref(service);
            }
            if (touSessionIsAlive(engine))
            {
                touSessionSetReady(engine);
                touSessionStart(engine);
            }
        }
    }
    touSessionRelease(engine);
}

static void processControl(tcpoverudpserver_carrier_t *carrier, const tou_wire_t *wire, const tou_settings_t *settings,
                           uint64_t now)
{
    tcpoverudpserver_tstate_t *ts = tunnelGetState(carrier->tunnel);
    if (atomicLoadRelaxed(&ts->stopping) || ts->workers[lineGetWID(carrier->line)].quiescing)
    {
        return;
    }
    if (wire->kind == kTouHello)
    {
        if (! touNonceIsZero(wire->server_nonce) || touNonceIsZero(wire->client_nonce) ||
            settings->data_shards != (ts->fec_enabled ? ts->fec_data_shards : 0) ||
            settings->parity_shards != (ts->fec_enabled ? ts->fec_parity_shards : 0))
        {
            return;
        }
        tcpoverudpserver_session_t *known = findSession(carrier, wire, false);
        if (known != NULL)
        {
            if (touSettingsEqual(&known->offered_settings, settings))
            {
                tcpoverudpserverCarrierControl(carrier,
                                               kTouChallenge,
                                               touSessionClientNonce(known->engine),
                                               touSessionServerNonce(known->engine),
                                               touSessionSettings(known->engine));
            }
            return;
        }
        if (carrier->pending)
        {
            if (memcmp(carrier->client_nonce, wire->client_nonce, kTouNonceSize) != 0 ||
                ! touSettingsEqual(&carrier->offered_settings, settings))
            {
                return;
            }
        }
        else
        {
            if (carrier->session_count >= kTouMaximumSessions)
            {
                return;
            }
            memcpy(carrier->client_nonce, wire->client_nonce, kTouNonceSize);
            touNonceGenerate(carrier->server_nonce);
            carrier->offered_settings          = *settings;
            carrier->pending_settings          = *settings;
            carrier->pending_settings.close_ms = min(settings->close_ms, ts->close_drain_timeout_ms);
            carrier->pending                   = true;
            if (! tcpoverudpserverArmPending(carrier, touDeadline(now, ts->no_recv_timeout_ms)))
            {
                tcpoverudpserverCarrierClose(carrier, true);
                return;
            }
        }
        tcpoverudpserverCarrierControl(
            carrier, kTouChallenge, carrier->client_nonce, carrier->server_nonce, &carrier->pending_settings);
    }
    else if (wire->kind == kTouConfirm)
    {
        tcpoverudpserver_session_t *known = findSession(carrier, wire, true);
        if (known != NULL)
        {
            if (touSettingsEqual(touSessionSettings(known->engine), settings))
            {
                tcpoverudpserverCarrierControl(carrier, kTouReady, wire->client_nonce, wire->server_nonce, settings);
            }
            return;
        }
        if (carrier->pending && now < carrier->pending_deadline &&
            memcmp(carrier->client_nonce, wire->client_nonce, kTouNonceSize) == 0 &&
            memcmp(carrier->server_nonce, wire->server_nonce, kTouNonceSize) == 0 &&
            touSettingsEqual(&carrier->pending_settings, settings))
        {
            promoteSession(carrier);
        }
    }
}

void tcpoverudpserverCarrierInput(tcpoverudpserver_carrier_t *carrier, sbuf_t *buf)
{
    if (! carrier->active)
    {
        bufferpoolReuseBuffer(carrier->pool, buf);
        return;
    }
    if (! bufferqueueTryPushBack(&carrier->input, &buf))
    {
        lineReuseBuffer(carrier->line, buf);
        tcpoverudpserverCarrierClose(carrier, true);
        return;
    }
    if (carrier->driving)
    {
        return;
    }
    tcpoverudpserverCarrierRetain(carrier);
    carrier->driving = true;
    while (carrier->active && (buf = bufferqueuePopFront(&carrier->input)) != NULL)
    {
        uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(carrier->line)));
        if (carrier->pending && now >= carrier->pending_deadline)
        {
            carrier->pending = false;
        }
        tou_wire_t wire;
        if (! touWireDecode(sbufGetRawPtr(buf), sbufGetLength(buf), &wire))
        {
            lineReuseBuffer(carrier->line, buf);
            continue;
        }
        if (wire.kind == kTouKcp || wire.kind == kTouFec)
        {
            tcpoverudpserver_session_t *session = findSession(carrier, &wire, true);
            if (session != NULL)
            {
                touSessionInput(session->engine, buf);
            }
            else
            {
                lineReuseBuffer(carrier->line, buf);
            }
        }
        else
        {
            tou_settings_t settings;
            bool           valid = (wire.kind == kTouHello || wire.kind == kTouConfirm) &&
                         touSettingsDecode(wire.body, wire.body_len, &settings);
            lineReuseBuffer(carrier->line, buf);
            if (valid)
            {
                processControl(carrier, &wire, &settings, now);
            }
        }
    }
    carrier->driving = false;
    tcpoverudpserverCarrierRelease(carrier);
}

static void serviceControl(tunnel_t *t, line_t *l, TunnelFlowRoutineEst callback)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerService && ls->session != NULL);
    tcpoverudpserver_carrier_t *carrier = ls->carrier;
    if (! carrier->active)
    {
        return;
    }
    line_t *line = carrier->line;
    lineRef(line);
    callback(t, line);
    lineUnref(line);
}

void tcpoverudpserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    serviceControl(t, l, tunnelPrevDownStreamEst);
}

void tcpoverudpserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    serviceControl(t, l, tunnelPrevDownStreamPause);
}

void tcpoverudpserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    serviceControl(t, l, tunnelPrevDownStreamResume);
}

void tcpoverudpserverRelayToServices(tcpoverudpserver_carrier_t *carrier, TunnelFlowRoutineEst callback, bool pressure)
{
    tou_session_t *engines[kTouMaximumSessions];
    size_t         count = 0;
    for (tcpoverudpserver_session_t *session = carrier->sessions; session != NULL; session = session->next)
    {
        engines[count++] = session->engine;
        touSessionRetain(session->engine);
    }
    for (size_t i = 0; i < count; ++i)
    {
        /* Resolve through the authoritative list after each callback; an earlier one may close all children. */
        for (tcpoverudpserver_session_t *session = carrier->sessions; session != NULL; session = session->next)
        {
            if (session->engine == engines[i] && session->service != NULL && session->init_entered)
            {
                line_t *service = session->service;
                if (pressure)
                {
                    session->carrier_pause_delivered = carrier->transport_paused;
                }
                lineRef(service);
                callback(carrier->tunnel, service);
                lineUnref(service);
                break;
            }
        }
        touSessionRelease(engines[i]);
    }
}

void tcpoverudpserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerCarrier && ls->carrier != NULL);
    tcpoverudpserver_carrier_t *carrier = ls->carrier;
    tcpoverudpserverCarrierRetain(carrier);
    carrier->transport_established = true;
    tcpoverudpserverRelayToServices(carrier, tunnelNextUpStreamEst, false);
    tcpoverudpserverCarrierRelease(carrier);
}
