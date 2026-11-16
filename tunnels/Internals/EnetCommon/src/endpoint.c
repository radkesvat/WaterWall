#include "EnetCommon/endpoint.h"

#include "EnetCommon/driver.h"
#include "EnetCommon/session.h"

#include "loggers/network_logger.h"

typedef struct enet_association_s enet_association_t;

typedef struct enet_endpoint_worker_s
{
    enet_association_t *associations; /* every session root of this worker, including detached drains */
    bool                quiescing;
} enet_endpoint_worker_t;

typedef struct enet_endpoint_tstate_s
{
    enet_settings_t         settings; /* immutable after construction */
    enet_endpoint_role_t    role;
    const enet_output_t    *output;
    atomic_bool             stopping;
    wid_t                   workers_count;
    enet_endpoint_worker_t *workers;
} enet_endpoint_tstate_t;

typedef enum enet_line_role_e
{
    kEnetApplicationLine = 1,
    kEnetCarrierLine,
} enet_line_role_t;

typedef struct enet_endpoint_lstate_s
{
    enet_association_t *association;
    enet_line_role_t    role;
} enet_endpoint_lstate_t;

/* Stable until the session's final reference runs destroy_user. */
struct enet_association_s
{
    tunnel_t           *tunnel;
    line_t             *application; /* client: borrowed. server: owned, NULL until ENet admits the peer */
    line_t             *carrier;     /* client: owned. server: borrowed, held by one physical reference */
    enet_session_t     *session;     /* NULL once the terminal callback has started */
    buffer_pool_t      *pool;        /* the owner worker's pool; outlives both lines */
    enet_association_t *prev;
    enet_association_t *next;
    wid_t               wid;
    bool                owned_init_entered; /* Init was sent on the line this node created */
    bool                carrier_finished;   /* the carrier's neighbour finished it, or was told it is finished */
    bool                carrier_established;
    bool                carrier_paused;
};

static void endpointLinestateDestroy(enet_endpoint_lstate_t *ls)
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

static bool endpointAdmissionOpen(const enet_endpoint_tstate_t *ts, wid_t wid)
{
    return ! atomicLoadRelaxed(&ts->stopping) && ! ts->workers[wid].quiescing &&
           wloopNormalDispatchAllowed(getWorkerLoop(wid));
}

/* Session callbacks. They run after the ENet call has returned. */

static void associationEmit(void *user, sbuf_t *packet)
{
    enet_association_t *a       = user;
    line_t             *carrier = a->carrier;
    if (a->carrier_finished)
    {
        bufferpoolReuseBuffer(a->pool, packet);
        return;
    }
    const enet_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    lineRef(carrier);
    ts->output->carrier_payload(a->tunnel, carrier, packet);
    lineUnref(carrier);
}

static void associationPayload(void *user, sbuf_t *payload)
{
    enet_association_t *a           = user;
    line_t             *application = a->application;
    if (application == NULL)
    {
        bufferpoolReuseBuffer(a->pool, payload);
        return;
    }
    const enet_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    lineRef(application);
    ts->output->application_payload(a->tunnel, application, payload);
    lineUnref(application);
}

static void associationPressure(void *user, bool paused)
{
    enet_association_t *a = user;
    /* The producer stays paused while either reason holds. The carrier's pause is already in force. */
    if (a->application == NULL || a->carrier_paused)
    {
        return;
    }
    const enet_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
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

/* ENet admitted the peer. Create the owned service line and open it toward the next node. */
static void serverPromote(enet_association_t *a)
{
    tunnel_t               *t  = a->tunnel;
    enet_endpoint_tstate_t *ts = tunnelGetState(t);
    if (a->carrier_finished || ! endpointAdmissionOpen(ts, a->wid))
    {
        enetSessionAbort(a->session, kEnetSessionAborted);
        return;
    }
    line_t *service = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), a->wid);
    serverCopyContext(service, a->carrier);
    enet_endpoint_lstate_t *service_ls = lineGetState(service, t);
    *service_ls                        = (enet_endpoint_lstate_t) {.association = a, .role = kEnetApplicationLine};
    a->application                     = service;

    /* Init can finish the service, the carrier or both. Each step checks the association again. */
    enet_session_t *session = a->session;
    enetSessionRetain(session);
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
    enetSessionRelease(session);
}

static void associationConnected(void *user)
{
    enet_association_t           *a  = user;
    const enet_endpoint_tstate_t *ts = tunnelGetState(a->tunnel);
    if (ts->role == kEnetServerEndpoint)
    {
        serverPromote(a);
    }
}

static void associationTerminal(void *user, enet_session_result_t result)
{
    enet_association_t     *a           = user;
    tunnel_t               *t           = a->tunnel;
    enet_endpoint_tstate_t *ts          = tunnelGetState(t);
    const enet_output_t    *output      = ts->output;
    const bool              client      = ts->role == kEnetClientEndpoint;
    line_t                 *application = a->application;
    line_t                 *carrier     = a->carrier;
    enet_session_t         *session     = a->session;

    if (result != kEnetSessionClosed && result != kEnetSessionPeerClosed && result != kEnetSessionAborted)
    {
        LOGD("Enet%s: session ended (result %d)", client ? "Client" : "Server", (int) result);
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
    enetSessionRelease(session);
}

static void associationDestroyUser(void *user)
{
    memoryFree(user);
}

/* Creates the association with its session and publishes it in the worker's inventory. */
static enet_association_t *associationCreate(tunnel_t *t, wid_t wid, line_t *application, line_t *carrier)
{
    enet_endpoint_tstate_t *ts         = tunnelGetState(t);
    enet_association_t     *a          = memoryAllocateZero(sizeof(*a));
    a->tunnel                          = t;
    a->application                     = application;
    a->carrier                         = carrier;
    a->wid                             = wid;
    a->pool                            = getWorkerBufferPool(wid);
    const enet_session_config_t config = {
        .settings = ts->settings,
        .client   = ts->role == kEnetClientEndpoint,
        .pool     = a->pool,
        .loop     = getWorkerLoop(wid),
    };
    const enet_session_callbacks_t callbacks = {
        .emit         = associationEmit,
        .payload      = associationPayload,
        .connected    = associationConnected,
        .pressure     = associationPressure,
        .terminal     = associationTerminal,
        .destroy_user = associationDestroyUser,
    };
    a->session = enetSessionCreate(&config, &callbacks, a);
    if (a->session == NULL)
    {
        memoryFree(a);
        return NULL;
    }
    enet_endpoint_worker_t *worker = &ts->workers[wid];
    a->next                        = worker->associations;
    if (a->next != NULL)
    {
        a->next->prev = a;
    }
    worker->associations = a;
    return a;
}

static bool clientAdmit(tunnel_t *t, line_t *application)
{
    enet_endpoint_tstate_t *ts  = tunnelGetState(t);
    const wid_t             wid = lineGetWID(application);
    assert(wid < ts->workers_count);
    enet_endpoint_lstate_t *application_ls = lineGetState(application, t);
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

    enet_association_t *a = associationCreate(t, wid, application, carrier);
    if (a == NULL)
    {
        lineDestroy(carrier);
        return false;
    }
    *application_ls                    = (enet_endpoint_lstate_t) {.association = a, .role = kEnetApplicationLine};
    enet_endpoint_lstate_t *carrier_ls = lineGetState(carrier, t);
    *carrier_ls                        = (enet_endpoint_lstate_t) {.association = a, .role = kEnetCarrierLine};

    enet_session_t *session = a->session;
    enetSessionRetain(session);
    lineRef(carrier);
    a->owned_init_entered = true;
    ts->output->init_owned(t, carrier);
    if (lineIsAlive(carrier) && enetSessionIsAlive(session))
    {
        enetSessionStart(session);
    }
    lineUnref(carrier);
    enetSessionRelease(session);
    /* Published. Reentry may already have closed the borrowed application. */
    return true;
}

void enetEndpointClientInit(tunnel_t *t, line_t *application)
{
    if (! clientAdmit(t, application))
    {
        const enet_endpoint_tstate_t *ts = tunnelGetState(t);
        ts->output->application_finish(t, application);
    }
}

void enetEndpointServerInit(tunnel_t *t, line_t *carrier)
{
    /* The incoming normal line belongs to the UDP source. The service line waits for ENet's connect event. */
    enet_endpoint_tstate_t *ts  = tunnelGetState(t);
    const wid_t             wid = lineGetWID(carrier);
    assert(lineIsOnCurrentWorker(carrier) && wid < ts->workers_count);
    enet_endpoint_lstate_t *ls = lineGetState(carrier, t);
    endpointLinestateDestroy(ls);
    enet_association_t *a = endpointAdmissionOpen(ts, wid) ? associationCreate(t, wid, NULL, carrier) : NULL;
    if (a == NULL)
    {
        ts->output->carrier_finish(t, carrier);
        return;
    }
    lineRef(carrier); /* physical reference only; the UDP owner destroys the line */
    *ls = (enet_endpoint_lstate_t) {.association = a, .role = kEnetCarrierLine};
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(carrier), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(carrier), IP_PROTO_UDP);
    enetSessionStart(a->session);
}

void enetEndpointApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetApplicationLine && ls->association != NULL);
    /* The session admits the complete payload before a pressure or output callback can reenter. */
    enetSessionSend(ls->association->session, buf);
}

void enetEndpointCarrierPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetCarrierLine && ls->association != NULL);
    if (ls->association->session == NULL)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    enetSessionInput(ls->association->session, buf);
}

void enetEndpointApplicationEst(tunnel_t *t, line_t *line)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetApplicationLine && ls->association != NULL);
    enet_association_t           *a  = ls->association;
    const enet_endpoint_tstate_t *ts = tunnelGetState(t);
    if (ts->output->carrier_est != NULL && ! a->carrier_finished)
    {
        endpointSignal(t, a->carrier, ts->output->carrier_est);
    }
}

void enetEndpointCarrierEst(tunnel_t *t, line_t *line)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetCarrierLine && ls->association != NULL);
    enet_association_t           *a  = ls->association;
    const enet_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Transport readiness, not protocol readiness. A server remembers it for a service that does not exist yet. */
    a->carrier_established = true;
    if (a->session != NULL && a->application != NULL)
    {
        endpointSignal(t, a->application, ts->output->application_est);
    }
}

void enetEndpointSetApplicationPaused(tunnel_t *t, line_t *line, bool paused)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetApplicationLine && ls->association != NULL);
    enet_association_t           *a  = ls->association;
    const enet_endpoint_tstate_t *ts = tunnelGetState(t);
    /* The stream's consumer is full or ready again: stop or restart datagram ingress at the UDP adapter. */
    if (! a->carrier_finished)
    {
        endpointSignal(t, a->carrier, paused ? ts->output->carrier_pause : ts->output->carrier_resume);
    }
}

void enetEndpointSetCarrierPaused(tunnel_t *t, line_t *line, bool paused)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetCarrierLine && ls->association != NULL);
    enet_association_t           *a  = ls->association;
    const enet_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Publish the reason first. The producer hears it only while the session's own hold is clear; neither reason
     * releases the other. */
    a->carrier_paused = paused;
    if (a->session != NULL && a->application != NULL && ! enetSessionIsPressured(a->session))
    {
        endpointSignal(t, a->application, paused ? ts->output->application_pause : ts->output->application_resume);
    }
}

void enetEndpointApplicationFinish(tunnel_t *t, line_t *line)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetApplicationLine && ls->association != NULL);
    enet_association_t     *a       = ls->association;
    enet_endpoint_tstate_t *ts      = tunnelGetState(t);
    enet_session_t         *session = a->session;
    enetSessionRetain(session);
    /* Clear both directions first. No later payload or pressure notice targets this application. */
    a->application = NULL;
    endpointLinestateDestroy(ls);
    if (ts->role == kEnetServerEndpoint)
    {
        /* This node created the service line. It is dead before this handler returns. */
        lineDestroy(line);
    }
    if (a->carrier_finished || atomicLoadRelaxed(&ts->stopping) || ts->workers[a->wid].quiescing)
    {
        enetSessionAbort(session, kEnetSessionAborted);
    }
    else
    {
        enetSessionAppFinish(session);
    }
    enetSessionRelease(session);
}

void enetEndpointCarrierFinish(tunnel_t *t, line_t *line)
{
    enet_endpoint_lstate_t *ls = lineGetState(line, t);
    assert(ls->role == kEnetCarrierLine && ls->association != NULL);
    enet_association_t           *a  = ls->association;
    const enet_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Never reflect Finish toward the side that sent it. */
    a->carrier_finished = true;
    if (a->session == NULL)
    {
        /* A terminal callback is closing the application side. This carrier still settles before its Finish
         * returns: an owned one dies here. */
        endpointLinestateDestroy(ls);
        if (ts->role == kEnetClientEndpoint)
        {
            lineDestroy(line);
        }
        return;
    }
    /* Abort settles synchronously: the terminal callback retires both lines before it returns. */
    enetSessionAbort(a->session, kEnetSessionAborted);
}

static void endpointOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    enet_endpoint_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

static void endpointOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                 context;
    enet_endpoint_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    ts->workers[wid].quiescing = true;
    for (enet_association_t *a = ts->workers[wid].associations; a != NULL; a = a->next)
    {
        enetSessionQuiesce(a->session);
    }
}

static void endpointOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    endpointOnWorkerQuiesce(t, wid, context);
    enet_endpoint_tstate_t *ts = tunnelGetState(t);
    /* Shutdown does not wait for graceful deadlines. Each abort removes its entry and destroys the owned line. */
    while (ts->workers[wid].associations != NULL)
    {
        enetSessionAbort(ts->workers[wid].associations->session, kEnetSessionAborted);
    }
}

static void endpointOnDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    enet_endpoint_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].associations != NULL))
        {
            LOGF("Enet%s: session roots remain at destruction", ts->role == kEnetClientEndpoint ? "Client" : "Server");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}

tunnel_t *enetEndpointCreate(node_t *node, enet_endpoint_role_t role, const enet_output_t *output)
{
    tunnel_t *t = tunnelCreate(node, sizeof(enet_endpoint_tstate_t), sizeof(enet_endpoint_lstate_t));
    if (! t)
    {
        return NULL;
    }
    enet_endpoint_tstate_t *ts        = tunnelGetState(t);
    const char             *node_type = role == kEnetClientEndpoint ? "EnetClient" : "EnetServer";
    ts->role                          = role;
    ts->output                        = output;
    if (! enetSettingsParse(&ts->settings, node->node_settings_json, node_type))
    {
        tunnelDestroy(t);
        return NULL;
    }
    if (! enetDriverInstall(&memoryAllocate, &memoryFree))
    {
        LOGF("%s: ENet refused the WaterWall allocator", node_type);
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
