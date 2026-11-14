#include "GnsCommon/endpoint.h"

#include "GnsCommon/port.h"
#include "GnsCommon/session.h"

#include "loggers/network_logger.h"

typedef struct gns_association_s gns_association_t;

typedef struct gns_endpoint_worker_s
{
    gns_association_t *associations; /* every session root of this worker, including detached drains */
    bool               quiescing;
} gns_endpoint_worker_t;

typedef struct gns_endpoint_tstate_s
{
    gns_settings_t         settings; /* immutable after construction */
    gns_endpoint_role_t    role;
    const gns_output_t    *output;
    atomic_bool            stopping;
    wid_t                  workers_count;
    gns_endpoint_worker_t *workers;
} gns_endpoint_tstate_t;

typedef enum gns_line_role_e
{
    kGnsApplicationLine = 1,
    kGnsCarrierLine,
} gns_line_role_t;

typedef struct gns_endpoint_lstate_s
{
    gns_association_t *association;
    gns_line_role_t    role;
} gns_endpoint_lstate_t;

/* Stable until the session's final reference runs destroy_user. */
struct gns_association_s
{
    tunnel_t          *tunnel;
    line_t            *application; /* client: borrowed. server: owned, NULL until GNS admits the peer */
    line_t            *carrier;     /* client: owned. server: borrowed, held by one physical reference */
    gns_session_t     *session;     /* NULL once the terminal callback has started */
    buffer_pool_t     *pool;        /* the owner worker's pool; outlives both lines */
    gns_association_t *prev;
    gns_association_t *next;
    wid_t              wid;
    bool               owned_init_entered; /* Init was sent on the line this node created */
    bool               carrier_finished;   /* the carrier's neighbour finished it, or was told it is finished */
    bool               carrier_established;
    bool               carrier_paused;
};

static void endpointLinestateDestroy(gns_endpoint_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

/* Calls one flow routine on a line that can die during the call. The caller touches no state afterwards unless it
 * checks the line or the association again. */
static void endpointSignal(tunnel_t *t, line_t *line, TunnelFlowRoutineEst signal)
{
    lineRef(line);
    signal(t, line);
    lineUnref(line);
}

static bool endpointAdmissionOpen(const gns_endpoint_tstate_t *ts, wid_t wid)
{
    return ! atomicLoadRelaxed(&ts->stopping) && ! ts->workers[wid].quiescing &&
           wloopNormalDispatchAllowed(getWorkerLoop(wid));
}

/* Session callbacks. They run after the GNS call has returned. */

static void associationEmit(void *user, sbuf_t *packet)
{
    gns_association_t *a       = user;
    line_t            *carrier = a->carrier;
    if (a->carrier_finished)
    {
        bufferpoolReuseBuffer(a->pool, packet);
        return;
    }
    const gns_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    lineRef(carrier);
    ts->output->carrier_payload(a->tunnel, carrier, packet);
    lineUnref(carrier);
}

static void associationPayload(void *user, sbuf_t *payload)
{
    gns_association_t *a           = user;
    line_t            *application = a->application;
    if (application == NULL)
    {
        bufferpoolReuseBuffer(a->pool, payload);
        return;
    }
    const gns_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    lineRef(application);
    ts->output->application_payload(a->tunnel, application, payload);
    lineUnref(application);
}

static void associationPressure(void *user, bool paused)
{
    gns_association_t *a = user;
    /* The producer stays paused while either reason holds. The carrier's pause is already in force. */
    if (a->application == NULL || a->carrier_paused)
    {
        return;
    }
    const gns_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    endpointSignal(a->tunnel, a->application, paused ? ts->output->application_pause : ts->output->application_resume);
}

static void serverCopyContext(line_t *service, line_t *carrier)
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
    /* The service carries a reliable stream; the carrier stays UDP. */
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

/* GNS admitted the peer. Create the owned service line and open it toward the next node. */
static void serverPromote(gns_association_t *a)
{
    tunnel_t              *t  = a->tunnel;
    gns_endpoint_tstate_t *ts = tunnelGetState(t);
    if (a->carrier_finished || ! endpointAdmissionOpen(ts, a->wid))
    {
        gnsSessionAbort(a->session, kGnsSessionAborted);
        return;
    }
    line_t *service = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), a->wid);
    serverCopyContext(service, a->carrier);
    gns_endpoint_lstate_t *service_ls = lineGetState(service, t);
    *service_ls                       = (gns_endpoint_lstate_t) {.association = a, .role = kGnsApplicationLine};
    a->application                    = service;

    /* Init can finish the service, the carrier or both. Each step checks the association again. */
    gns_session_t *session = a->session;
    gnsSessionRetain(session);
    lineRef(service);
    a->owned_init_entered = true;
    ts->output->init_owned(t, service);
    bool attached = lineIsAlive(service) && a->application == service;
    if (attached && a->carrier_paused)
    {
        /* The carrier paused before the service existed. Deliver that hold now. */
        ts->output->application_pause(t, service);
        attached = lineIsAlive(service) && a->application == service;
    }
    if (attached && a->carrier_established)
    {
        ts->output->application_est(t, service);
    }
    lineUnref(service);
    gnsSessionRelease(session);
}

static void associationConnected(void *user)
{
    gns_association_t           *a  = user;
    const gns_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    if (ts->role == kGnsServerEndpoint)
    {
        serverPromote(a);
    }
}

static void associationTerminal(void *user, gns_session_result_t result)
{
    gns_association_t     *a           = user;
    tunnel_t              *t           = a->tunnel;
    gns_endpoint_tstate_t *ts          = tunnelGetState(t);
    const gns_output_t    *output      = ts->output;
    const bool             client      = ts->role == kGnsClientEndpoint;
    line_t                *application = a->application;
    line_t                *carrier     = a->carrier;
    gns_session_t         *session     = a->session;

    if (result != kGnsSessionClosed && result != kGnsSessionPeerClosed && result != kGnsSessionAborted)
    {
        LOGD("Gns%s: session ended (result %d)", client ? "Client" : "Server", (int) result);
    }

    /* Retire the inventory entry and the application link before any callout. The carrier keeps resolving this
     * terminal context, where session is NULL, until its own cleanup below. */
    if (a->prev != NULL)
    {
        a->prev->next = a->next;
    }
    else
    {
        ts->workers[a->wid].associations = a->next;
    }
    if (a->next != NULL)
    {
        a->next->prev = a->prev;
    }
    a->prev = a->next = NULL;
    a->session        = NULL;
    a->application    = NULL;

    lineRef(carrier);
    if (application != NULL)
    {
        lineRef(application);
        endpointLinestateDestroy(lineGetState(application, t));
        if (client)
        {
            /* Borrowed application: tell its owner and never destroy it. */
            if (lineIsAlive(application))
            {
                output->application_finish(t, application);
            }
        }
        else
        {
            /* Owned service line: its neighbour hears Finish only if it saw Init, then the line dies here. */
            if (a->owned_init_entered)
            {
                output->application_finish(t, application);
            }
            if (lineIsAlive(application))
            {
                lineDestroy(application);
            }
        }
        lineUnref(application);
    }

    if (lineIsAlive(carrier))
    {
        endpointLinestateDestroy(lineGetState(carrier, t));
        if (client)
        {
            /* Owned carrier: it is dead when this returns, whoever asked for the end. */
            if (a->owned_init_entered && ! a->carrier_finished)
            {
                a->carrier_finished = true;
                output->carrier_finish(t, carrier);
            }
            lineDestroy(carrier);
        }
        else if (! a->carrier_finished)
        {
            /* Borrowed carrier: finish toward its owner unless the owner finished it first. */
            a->carrier_finished = true;
            output->carrier_finish(t, carrier);
        }
    }
    if (! client)
    {
        lineUnref(carrier); /* the physical reference taken at Init */
    }
    lineUnref(carrier);
    gnsSessionRelease(session);
}

static void associationDestroyUser(void *user)
{
    memoryFree(user);
}

/* Creates the association with its session and publishes it in the worker's inventory. */
static gns_association_t *associationCreate(tunnel_t *t, wid_t wid, line_t *application, line_t *carrier)
{
    gns_endpoint_tstate_t *ts         = tunnelGetState(t);
    gns_association_t     *a          = memoryAllocateZero(sizeof(*a));
    a->tunnel                         = t;
    a->application                    = application;
    a->carrier                        = carrier;
    a->wid                            = wid;
    a->pool                           = getWorkerBufferPool(wid);
    const gns_session_config_t config = {
        .settings = ts->settings,
        .client   = ts->role == kGnsClientEndpoint,
        .wid      = wid,
        .pool     = a->pool,
        .loop     = getWorkerLoop(wid),
    };
    const gns_session_callbacks_t callbacks = {
        .emit         = associationEmit,
        .payload      = associationPayload,
        .connected    = associationConnected,
        .pressure     = associationPressure,
        .terminal     = associationTerminal,
        .destroy_user = associationDestroyUser,
    };
    a->session = gnsSessionCreate(&config, &callbacks, a);
    if (a->session == NULL)
    {
        memoryFree(a);
        return NULL;
    }
    gns_endpoint_worker_t *worker = &ts->workers[wid];
    a->next                       = worker->associations;
    if (a->next != NULL)
    {
        a->next->prev = a;
    }
    worker->associations = a;
    return a;
}

static bool clientAdmit(tunnel_t *t, line_t *application)
{
    gns_endpoint_tstate_t *ts  = tunnelGetState(t);
    const wid_t            wid = lineGetWID(application);
    assert(wid < ts->workers_count);
    gns_endpoint_lstate_t *application_ls = lineGetState(application, t);
    endpointLinestateDestroy(application_ls);
    if (! endpointAdmissionOpen(ts, wid))
    {
        return false;
    }

    line_t *carrier = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    addresscontextCopy(lineGetSourceAddressContext(carrier), lineGetSourceAddressContext(application));
    addresscontextCopy(lineGetDestinationAddressContext(carrier), lineGetDestinationAddressContext(application));
    carrier->routing_context.local_listener_port = application->routing_context.local_listener_port;
    carrier->routing_context.peer_source_port    = application->routing_context.peer_source_port;
    lineCopyUsers(carrier, application);
    carrier->prefer_ordinary_read_u = application->prefer_ordinary_read_u;
    carrier->prefer_ordinary_read_d = application->prefer_ordinary_read_d;
    carrier->fallback_mode          = application->fallback_mode;
    if (lineHasCloseLingerReason(application, kLineCloseLingerPeerWriteShutdown))
    {
        lineRequestCloseLinger(carrier, kLineCloseLingerPeerWriteShutdown);
    }
    /* The application carries a reliable stream; the carrier is UDP. */
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(application), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(application), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(carrier), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(carrier), IP_PROTO_UDP);

    gns_association_t *a = associationCreate(t, wid, application, carrier);
    if (a == NULL)
    {
        lineDestroy(carrier);
        return false;
    }
    *application_ls                   = (gns_endpoint_lstate_t) {.association = a, .role = kGnsApplicationLine};
    gns_endpoint_lstate_t *carrier_ls = lineGetState(carrier, t);
    *carrier_ls                       = (gns_endpoint_lstate_t) {.association = a, .role = kGnsCarrierLine};

    gns_session_t *session = a->session;
    gnsSessionRetain(session);
    lineRef(carrier);
    a->owned_init_entered = true;
    ts->output->init_owned(t, carrier);
    if (lineIsAlive(carrier) && gnsSessionIsAlive(session))
    {
        gnsSessionStart(session);
    }
    lineUnref(carrier);
    gnsSessionRelease(session);
    /* Published. Reentry may already have closed the borrowed application. */
    return true;
}

void gnsEndpointClientInit(tunnel_t *t, line_t *application)
{
    if (! clientAdmit(t, application))
    {
        const gns_endpoint_tstate_t *ts = tunnelGetState(t);
        ts->output->application_finish(t, application);
    }
}

void gnsEndpointServerInit(tunnel_t *t, line_t *carrier)
{
    /* The incoming normal line belongs to the UDP source. The service line waits for the native handshake. */
    gns_endpoint_tstate_t *ts  = tunnelGetState(t);
    const wid_t            wid = lineGetWID(carrier);
    assert(lineIsOnCurrentWorker(carrier) && wid < ts->workers_count);
    gns_endpoint_lstate_t *ls = lineGetState(carrier, t);
    endpointLinestateDestroy(ls);
    gns_association_t *a = endpointAdmissionOpen(ts, wid) ? associationCreate(t, wid, NULL, carrier) : NULL;
    if (a == NULL)
    {
        ts->output->carrier_finish(t, carrier);
        return;
    }
    lineRef(carrier); /* physical reference only; the UDP owner destroys the line */
    *ls = (gns_endpoint_lstate_t) {.association = a, .role = kGnsCarrierLine};
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(carrier), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(carrier), IP_PROTO_UDP);
    gnsSessionStart(a->session);
}

void gnsEndpointApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsApplicationLine && ls->association != NULL);
    /* The session admits the complete payload before a pressure or output callback can reenter. */
    gnsSessionSend(ls->association->session, buf);
}

void gnsEndpointCarrierPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsCarrierLine && ls->association != NULL);
    if (ls->association->session == NULL)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    gnsSessionInput(ls->association->session, buf);
}

void gnsEndpointApplicationEst(tunnel_t *t, line_t *line)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsApplicationLine && ls->association != NULL);
    gns_association_t           *a  = ls->association;
    const gns_endpoint_tstate_t *ts = tunnelGetState(t);
    if (ts->output->carrier_est != NULL && ! a->carrier_finished)
    {
        endpointSignal(t, a->carrier, ts->output->carrier_est);
    }
}

void gnsEndpointCarrierEst(tunnel_t *t, line_t *line)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsCarrierLine && ls->association != NULL);
    gns_association_t           *a  = ls->association;
    const gns_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Transport readiness, not protocol readiness. A server remembers it for a service that does not exist yet. */
    a->carrier_established = true;
    if (a->session != NULL && a->application != NULL)
    {
        endpointSignal(t, a->application, ts->output->application_est);
    }
}

void gnsEndpointSetApplicationPaused(tunnel_t *t, line_t *line, bool paused)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsApplicationLine && ls->association != NULL);
    gns_association_t           *a  = ls->association;
    const gns_endpoint_tstate_t *ts = tunnelGetState(t);
    /* The stream's consumer is full or ready again: stop or restart datagram ingress at the UDP adapter. */
    if (! a->carrier_finished)
    {
        endpointSignal(t, a->carrier, paused ? ts->output->carrier_pause : ts->output->carrier_resume);
    }
}

void gnsEndpointSetCarrierPaused(tunnel_t *t, line_t *line, bool paused)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsCarrierLine && ls->association != NULL);
    gns_association_t           *a  = ls->association;
    const gns_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Publish the reason first. The producer hears it only while the session's own hold is clear; neither reason
     * releases the other. */
    a->carrier_paused = paused;
    if (a->session != NULL && a->application != NULL && ! gnsSessionIsPressured(a->session))
    {
        endpointSignal(t, a->application, paused ? ts->output->application_pause : ts->output->application_resume);
    }
}

void gnsEndpointApplicationFinish(tunnel_t *t, line_t *line)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsApplicationLine && ls->association != NULL);
    gns_association_t     *a       = ls->association;
    gns_endpoint_tstate_t *ts      = tunnelGetState(t);
    gns_session_t         *session = a->session;
    gnsSessionRetain(session);
    /* Clear both directions first. No later payload or pressure notice targets this application. */
    a->application = NULL;
    endpointLinestateDestroy(ls);
    if (ts->role == kGnsServerEndpoint)
    {
        /* This node created the service line. It is dead before this handler returns. */
        lineDestroy(line);
    }
    if (a->carrier_finished || atomicLoadRelaxed(&ts->stopping) || ts->workers[a->wid].quiescing)
    {
        gnsSessionAbort(session, kGnsSessionAborted);
    }
    else
    {
        gnsSessionAppFinish(session);
    }
    gnsSessionRelease(session);
}

void gnsEndpointCarrierFinish(tunnel_t *t, line_t *line)
{
    gns_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kGnsCarrierLine && ls->association != NULL);
    gns_association_t           *a  = ls->association;
    const gns_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Never reflect Finish toward the side that sent it. */
    a->carrier_finished = true;
    if (a->session == NULL)
    {
        /* A terminal callback is closing the application side. This carrier still settles before its Finish
         * returns: an owned one dies here. */
        endpointLinestateDestroy(ls);
        if (ts->role == kGnsClientEndpoint)
        {
            lineDestroy(line);
        }
        return;
    }
    /* Abort settles synchronously: the terminal callback retires both lines before it returns. */
    gnsSessionAbort(a->session, kGnsSessionAborted);
}

static void endpointOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                context;
    gns_endpoint_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

static void endpointOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                context;
    gns_endpoint_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    ts->workers[wid].quiescing = true;
    for (gns_association_t *a = ts->workers[wid].associations; a != NULL; a = a->next)
    {
        gnsSessionQuiesce(a->session);
    }
}

static void endpointOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    endpointOnWorkerQuiesce(t, wid, context);
    gns_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Shutdown does not wait for graceful deadlines. Each abort removes its entry and destroys the owned line. */
    while (ts->workers[wid].associations != NULL)
    {
        gnsSessionAbort(ts->workers[wid].associations->session, kGnsSessionAborted);
    }
}

static void endpointOnDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                context;
    gns_endpoint_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].associations != NULL))
        {
            LOGF("Gns%s: session roots remain at destruction", ts->role == kGnsClientEndpoint ? "Client" : "Server");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    gnsRuntimeRelease();
    tunnelDestroy(t);
}

tunnel_t *gnsEndpointCreate(node_t *node, gns_endpoint_role_t role, const gns_output_t *output)
{
    tunnel_t *t = tunnelCreate(node, sizeof(gns_endpoint_tstate_t), sizeof(gns_endpoint_lstate_t));
    if (! t)
    {
        return NULL;
    }
    gns_endpoint_tstate_t *ts        = tunnelGetState(t);
    const char            *node_type = role == kGnsClientEndpoint ? "GnsClient" : "GnsServer";
    ts->role                         = role;
    ts->output                       = output;
    if (! gnsSettingsParse(&ts->settings, node->node_settings_json, node_type))
    {
        tunnelDestroy(t);
        return NULL;
    }
    /* The library and the table behind its accept callback are shared by every GNS node of the process. */
    if (! gnsRuntimeAcquire(node_type))
    {
        tunnelDestroy(t);
        return NULL;
    }
    atomic_init(&ts->stopping, false);
    ts->workers_count   = getWorkersCount();
    ts->workers         = memoryAllocateZero(sizeof(*ts->workers) * ts->workers_count);
    t->onQuiesceRequest = endpointOnQuiesceRequest;
    t->onWorkerQuiesce  = endpointOnWorkerQuiesce;
    t->onWorkerStop     = endpointOnWorkerStop;
    t->onDestroy        = endpointOnDestroy;
    return t;
}
