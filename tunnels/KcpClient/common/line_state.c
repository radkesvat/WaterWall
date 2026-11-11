#include "structure.h"

#include "loggers/network_logger.h"

void kcpclientLinestateDestroy(kcpclient_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void kcpclientDetachApplication(kcpclient_session_t *session, bool notify)
{
    line_t *application = session->application;
    if (application == NULL)
        return;
    /* Clear both directions before Finish; the borrowed owner may destroy immediately. */
    session->application = NULL;
    kcpclientLinestateDestroy(lineGetState(application, session->tunnel));
    if (notify)
        tunnelPrevDownStreamFinish(session->tunnel, application);
}

void kcpclientSignalApplication(kcpclient_session_t *session, LineTaskFnNoBuf signal)
{
    line_t *application = session->application;
    if (application == NULL)
        return;
    lineRef(application);
    signal(session->tunnel, application);
    /* No state is touched after a callback which can retire the association. */
    lineUnref(application);
}

void kcpclientSetCarrierPaused(kcpclient_session_t *session, bool paused)
{
    session->carrier_paused = paused;
    if (session->application != NULL && ! touSessionIsPressured(session->driver))
    {
        kcpclientSignalApplication(session, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume);
    }
}

static void clientEmit(void *user, sbuf_t *packet)
{
    kcpclient_session_t *session   = user;
    line_t              *transport = session->transport;
    assert(transport != NULL && session->next_init_entered);
    lineRef(transport);
    tunnelNextUpStreamPayload(session->tunnel, transport, packet);
    lineUnref(transport);
}

static void clientPayload(void *user, sbuf_t *payload)
{
    kcpclient_session_t *session     = user;
    line_t              *application = session->application;
    if (application == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(session->wid), payload);
        return;
    }
    lineRef(application);
    tunnelPrevDownStreamPayload(session->tunnel, application, payload);
    lineUnref(application);
}

static void clientPeerClose(void *user)
{
    kcpclientDetachApplication(user, true);
}

static void clientPressure(void *user, bool paused)
{
    kcpclient_session_t *session = user;
    if (! session->carrier_paused)
    {
        kcpclientSignalApplication(session, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume);
    }
}

static void clientTerminal(void *user, tou_result_t result)
{
    kcpclient_session_t *session     = user;
    tunnel_t            *t           = session->tunnel;
    kcpclient_tstate_t  *ts          = tunnelGetState(t);
    line_t              *transport   = session->transport;
    line_t              *application = session->application;
    tou_session_t       *driver      = session->driver;

    if (result != kTouConfirmed && result != kTouPeerDrained)
        LOGD("KcpClient: session aborted (reason %d)", (int) result);

    lineRef(transport);
    if (application != NULL)
        lineRef(application);
    /* Retire application admission and the authoritative inventory before callouts.
     * The transport keeps only a terminal context until its own cleanup. */
    if (session->prev != NULL)
        session->prev->next = session->next;
    else
        ts->workers[session->wid].sessions = session->next;
    if (session->next != NULL)
        session->next->prev = session->prev;
    session->prev = session->next = NULL;
    session->transport            = NULL;
    session->driver               = NULL;
    session->application          = NULL;
    if (application != NULL)
        kcpclientLinestateDestroy(lineGetState(application, t));

    /* Close application-owner admission before transport cleanup can synchronously
     * trigger another read/close through a shared neighboring resource. Transport
     * callbacks still resolve this terminal context until its own Finish below. */
    if (application != NULL)
    {
        if (lineIsAlive(application))
            tunnelPrevDownStreamFinish(t, application);
        lineUnref(application);
    }
    if (lineIsAlive(transport))
    {
        kcpclientLinestateDestroy(lineGetState(transport, t));
        if (session->next_init_entered && ! session->transport_finished)
            tunnelNextUpStreamFinish(t, transport);
        lineDestroy(transport);
    }
    lineUnref(transport);
    touSessionRelease(driver);
}

static void clientDestroyUser(void *user)
{
    memoryFree(user);
}

bool kcpclientSessionCreate(tunnel_t *t, line_t *application)
{
    kcpclient_tstate_t *ts  = tunnelGetState(t);
    const wid_t         wid = lineGetWID(application);
    assert(wid < ts->workers_count);
    kcpclient_worker_t *worker         = &ts->workers[wid];
    kcpclient_lstate_t *application_ls = lineGetState(application, t);
    kcpclientLinestateDestroy(application_ls);
    if (atomicLoadRelaxed(&ts->stopping) || worker->quiescing || ! wloopNormalDispatchAllowed(getWorkerLoop(wid)))
        return false;

    line_t *transport = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    addresscontextCopy(lineGetSourceAddressContext(transport), lineGetSourceAddressContext(application));
    addresscontextCopy(lineGetDestinationAddressContext(transport), lineGetDestinationAddressContext(application));
    transport->routing_context.local_listener_port = application->routing_context.local_listener_port;
    transport->routing_context.peer_source_port    = application->routing_context.peer_source_port;
    lineCopyUsers(transport, application);
    transport->prefer_ordinary_read_u = application->prefer_ordinary_read_u;
    transport->prefer_ordinary_read_d = application->prefer_ordinary_read_d;
    transport->fallback_mode          = application->fallback_mode;
    if (lineHasCloseLingerReason(application, kLineCloseLingerPeerWriteShutdown))
        lineRequestCloseLinger(transport, kLineCloseLingerPeerWriteShutdown);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(application), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(application), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(transport), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(transport), IP_PROTO_UDP);

    kcpclient_session_t *session = memoryAllocateZero(sizeof(*session));
    session->tunnel              = t;
    session->application         = application;
    session->transport           = transport;
    session->wid                 = wid;
    tou_config_t config          = {
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
                 .pool                      = lineGetBufferPool(transport),
                 .loop                      = getWorkerLoop(wid),
    };
    const tou_callbacks_t callbacks = {
        .emit         = clientEmit,
        .payload      = clientPayload,
        .peer_close   = clientPeerClose,
        .pressure     = clientPressure,
        .terminal     = clientTerminal,
        .destroy_user = clientDestroyUser,
    };
    uint8_t       client_nonce[kTouNonceSize];
    const uint8_t server_nonce[kTouNonceSize] = {0};
    touNonceGenerate(client_nonce);
    session->driver = touSessionCreate(&config, &callbacks, session, true, client_nonce, server_nonce, NULL);
    if (session->driver == NULL)
    {
        memoryFree(session);
        lineDestroy(transport);
        return false;
    }

    *application_ls                  = (kcpclient_lstate_t) {.session = session, .role = kKcpClientApplication};
    kcpclient_lstate_t *transport_ls = lineGetState(transport, t);
    *transport_ls                    = (kcpclient_lstate_t) {.session = session, .role = kKcpClientTransport};
    session->next                    = worker->sessions;
    if (session->next != NULL)
        session->next->prev = session;
    worker->sessions = session;

    tou_session_t *driver = session->driver;
    touSessionRetain(driver);
    lineRef(transport);
    session->next_init_entered = true;
    tunnelNextUpStreamInit(t, transport);
    if (lineIsAlive(transport) && touSessionIsAlive(driver))
        touSessionStart(driver);
    lineUnref(transport);
    touSessionRelease(driver);
    /* Successful publication; reentry may already have closed the borrowed application. */
    return true;
}
