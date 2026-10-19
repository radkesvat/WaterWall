/* Real UserController payload and idle-sweep paths for authentication_sync_test.
 * The fixture head owns each normal line; UserController borrows it. */
#include "UserController/structure.h"
#include "authentication_sync_peer.h"
#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static uint64_t delivered[2];
static unsigned frames;
static unsigned frame_lengths[1024];
static uint8_t  frame_marks[1024];
static bool     close_in_payload;
static bool     close_in_resume;
static bool     check_resume_progress;
static unsigned pauses, resumes;
static unsigned reverse_borrower_finishes;

static void reverseBorrowerFinished(tunnel_t *t, line_t *l)
{
    discard t;
    require(lineIsAlive(l), "reverse borrower must finish before creator destroys line");
    ++reverse_borrower_finishes;
}

static void initialized(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void finished(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}

static void consumed(tunnel_t *t, line_t *l, sbuf_t *b)
{
    tunnel_t *controller = t->prev != NULL ? t->prev : t->next;
    unsigned  direction  = t == controller->next ? 0 : 1;
    delivered[direction] += sbufGetLength(b);
    require(frames < 1024, "controller fixture frame capacity");
    frame_lengths[frames] = sbufGetLength(b);
    frame_marks[frames++] = sbufGetLength(b) != 0 ? sbufGetMutablePtr(b)[0] : 0;
    lineReuseBuffer(l, b);
    if (close_in_payload)
    {
        close_in_payload = false;
        usercontrollerCloseLine(controller, l, kUserControllerCloseInternal);
    }
}

static void paused(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pauses;
}

static void resumed(tunnel_t *t, line_t *l)
{
    ++resumes;
    tunnel_t *controller = t->next != NULL ? t->next : t->prev;
    if (check_resume_progress)
    {
        check_resume_progress           = false;
        usercontroller_lstate_t *ls     = lineGetState(l, controller);
        traffic_shaper_t        *shaper = &ls->directions[t == controller->prev ? 0 : 1].shaper;
        require(trafficshaperPending(shaper) != 0 && (shaper->continuation != NULL || shaper->timer != NULL),
                "external Resume must schedule retained datagrams before notifying producer");
    }
    if (close_in_resume)
    {
        close_in_resume = false;
        usercontrollerCloseLine(controller, l, kUserControllerCloseInternal);
    }
}

tunnel_t *authTestControllerCreate(tunnel_t *auth)
{
    tunnel_t *controller = tunnelCreate(NULL, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t));
    tunnel_t *head = tunnelCreate(NULL, 0, 0), *tail = tunnelCreate(NULL, 0, 0);
    require(controller != NULL && head != NULL && tail != NULL, "controller fixture allocation");
    head->fnFinD           = finished;
    head->fnInitD          = initialized;
    head->fnPayloadD       = consumed;
    head->fnPauseD         = paused;
    head->fnResumeD        = resumed;
    tail->fnInitU          = initialized;
    tail->fnFinU           = initialized;
    tail->fnPayloadU       = consumed;
    tail->fnPauseU         = paused;
    tail->fnResumeU        = resumed;
    controller->fnInitU    = usercontrollerTunnelUpStreamInit;
    controller->fnFinU     = usercontrollerTunnelUpStreamFinish;
    controller->fnPayloadU = usercontrollerTunnelUpStreamPayload;
    controller->fnInitD    = usercontrollerTunnelDownStreamInit;
    controller->fnFinD     = usercontrollerTunnelDownStreamFinish;
    controller->fnPayloadD = usercontrollerTunnelDownStreamPayload;
    controller->fnPauseU   = usercontrollerTunnelUpStreamPause;
    controller->fnResumeU  = usercontrollerTunnelUpStreamResume;
    controller->fnPauseD   = usercontrollerTunnelDownStreamPause;
    controller->fnResumeD  = usercontrollerTunnelDownStreamResume;
    tunnelBind(head, controller);
    tunnelBind(controller, tail);
    usercontroller_tstate_t *ts = tunnelGetState(controller);
    ts->auth_client_tunnel      = auth;
    ts->fixed_payload_mode      = kUserControllerPayloadStream;
    ts->worker_count            = getWorkersCount();
    ts->worker_states           = memoryAllocateZero(sizeof(*ts->worker_states) * ts->worker_count);
    return controller;
}

line_t *authTestControllerOpen(tunnel_t *controller, tunnel_chain_t *chain)
{
    usercontroller_tstate_t *ts   = tunnelGetState(controller);
    line_t                  *line = lineCreate(chain->line_pools, 0);
    lineRef(line); /* Caller observes logical death after callbacks. */
    user_handle_t handle = {.generation = authenticationclientUsersGeneration(ts->auth_client_tunnel), .user_id = 42};
    lineAddUser(line, &handle, NULL, NULL);
    tunnelUpStreamInit(controller, line);
    return line;
}

void authTestControllerPayload(tunnel_t *controller, line_t *line)
{
    sbuf_t *b = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(b, 1);
    sbufGetMutablePtr(b)[0] = 42;
    tunnelUpStreamPayload(controller, line, b);
}

void authTestControllerSweep(tunnel_t *controller)
{
    wtimer_t *timer = wtimerAdd(getWorkerLoop(0), usercontrollerSweepTimerCallback, 1000, 1);
    require(timer != NULL, "controller sweep timer");
    weventSetUserData(timer, controller);
    usercontrollerSweepTimerCallback(timer);
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

void authTestControllerDestroy(tunnel_t *controller)
{
    usercontroller_tstate_t *ts = tunnelGetState(controller);
    for (wid_t wid = 0; wid < ts->worker_count; ++wid)
        require(ts->worker_states[wid].line_count == 0, "controller retained line references");
    tunnelDestroy(controller->prev);
    tunnelDestroy(controller->next);
    usercontrollerTunnelDestroy(controller, wwLifecycleProcessShutdown());
}

static void controllerTraceReset(void)
{
    memoryZero(delivered, sizeof(delivered));
    frames = pauses = resumes = 0;
    close_in_payload = close_in_resume = false;
    check_resume_progress              = false;
}

static void controllerSend(tunnel_t *t, line_t *l, unsigned length, uint8_t mark, bool upstream)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(l), length, 0);
    sbufSetLength(buf, length);
    if (length != 0)
        memset(sbufGetMutablePtr(buf), mark, length);
    if (upstream)
        tunnelUpStreamPayload(t, l, buf);
    else
        tunnelDownStreamPayload(t, l, buf);
}

static void controllerClose(tunnel_t *t, line_t *l)
{
    if (lineIsAlive(l))
        tunnelDownStreamFin(t, l);
    require(! lineIsAlive(l), "borrowed controller close did not reach line owner");
    lineUnref(l);
}

static user_stat_t controllerStats(tunnel_t *auth)
{
    user_handle_t handle = {.generation = authenticationclientUsersGeneration(auth), .user_id = 42};
    user_stat_t   stats;
    require(authenticationclientUserGetStats(auth, &handle, &stats), "controller account stats");
    return stats;
}

static void controllerPolicy(tunnel_t *auth, uint64_t up, uint64_t down, uint64_t quota)
{
    user_update_t update     = {.mask    = kUserUpdateLimit | kUserUpdateStats | kUserUpdateTimeInfo | kUserUpdateEnabled,
                                .enabled = true};
    update.limit.bandwidth.u = up;
    update.limit.bandwidth.d = down;
    update.limit.traffic.u   = quota;
    authTestControllerUpdateUser(auth, &update);
}

static void controllerConsumerPressure(tunnel_t *t, line_t *l, bool upstream, bool pause)
{
    if (upstream)
    {
        if (pause)
            tunnelDownStreamPause(t, l);
        else
            tunnelDownStreamResume(t, l);
    }
    else if (pause)
        tunnelUpStreamPause(t, l);
    else
        tunnelUpStreamResume(t, l);
}

static void controllerDatagramPressureCases(tunnel_t *auth, tunnel_chain_t *chain, void (*advance)(unsigned))
{
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        const bool upstream = direction == 0;
        controllerTraceReset();
        controllerPolicy(auth, 0, 0, 0);
        controllerPolicy(auth, 1000, 1000, 0);
        tunnel_t *a                                                         = authTestControllerCreate(auth);
        ((usercontroller_tstate_t *) tunnelGetState(a))->fixed_payload_mode = kUserControllerPayloadDatagram;
        line_t *first                                                       = authTestControllerOpen(a, chain);
        controllerSend(a, first, 100, 'b', upstream);
        require(delivered[direction] == 100, "datagram initial burst");
        for (unsigned i = 0; i < 256; ++i)
            controllerSend(a, first, 1, 'q', upstream);
        controllerSend(a, first, 1, 'x', upstream);
        usercontroller_lstate_t *ls = lineGetState(first, a);
        require(lineIsAlive(first) && trafficshaperPending(&ls->directions[direction].shaper) == 256 && pauses == 0 &&
                    resumes == 0,
                "local datagram backlog must admit up to its bound without pausing the producer");
        user_stat_t stats = controllerStats(auth);
        require((upstream ? stats.traffic.u : stats.traffic.d) == 100, "retained or overflow datagram charged quota");
        controllerPolicy(auth, 0, 0, 0);
        advance(100);
        for (unsigned i = 0; i < 256; ++i)
            advance(0);
        require(frames == 257 && delivered[direction] == 356 && pauses == 0 && resumes == 0,
                "datagram drain lost accepted packets or emitted a local Resume");
        for (unsigned i = 1; i < frames; ++i)
            require(frame_lengths[i] == 1 && frame_marks[i] == 'q', "overflow changed the accepted datagram FIFO");
        require(trafficshaperPending(&ls->directions[direction].shaper) == 0 && ls->directions[direction].ticket == 0 &&
                    ls->budget.used.entries == 0,
                "final datagram handoff retained its waiter or buffer budget");
        controllerClose(a, first);
        authTestControllerDestroy(a);

        /* An external consumer hold still gates this queue and yields its fair
         * turn. Releasing that hold must notify the producer despite backlog. */
        controllerTraceReset();
        controllerPolicy(auth, 100, 100, 0);
        a                                                                   = authTestControllerCreate(auth);
        tunnel_t *b                                                         = authTestControllerCreate(auth);
        ((usercontroller_tstate_t *) tunnelGetState(a))->fixed_payload_mode = kUserControllerPayloadDatagram;
        ((usercontroller_tstate_t *) tunnelGetState(b))->fixed_payload_mode = kUserControllerPayloadDatagram;
        first                                                               = authTestControllerOpen(a, chain);
        line_t *second                                                      = authTestControllerOpen(b, chain);
        controllerSend(a, first, 11, 'a', upstream);
        controllerConsumerPressure(a, first, upstream, true);
        controllerConsumerPressure(a, first, upstream, true);
        controllerSend(b, second, 10, 'b', upstream);
        advance(1000);
        require(frames == 1 && frame_marks[0] == 'b' && delivered[direction] == 10 && pauses == 1 && resumes == 0,
                "consumer Pause failed to gate datagrams, yield its fair turn, or forward producer pressure");
        ls = lineGetState(first, a);
        require(ls->directions[direction].shaper.timer == NULL && ls->directions[direction].shaper.continuation == NULL,
                "externally paused datagrams must not poll for credit");
        check_resume_progress = true;
        controllerConsumerPressure(a, first, upstream, false);
        require(! check_resume_progress && pauses == 1 && resumes == 1,
                "consumer Resume must reach producer while datagrams remain queued");
        advance(0);
        advance(100);
        require(frames == 2 && frame_lengths[1] == 11 && frame_marks[1] == 'a' && delivered[direction] == 21 &&
                    pauses == 1 && resumes == 1 && ls->directions[direction].ticket == 0,
                "resumed datagram did not drain whole and settle its final ticket without extra pressure");
        controllerClose(a, first);
        controllerClose(b, second);
        authTestControllerDestroy(a);
        authTestControllerDestroy(b);

        /* Producer Resume can synchronously close after progress is arranged.
         * The queued packet is discarded without charging or a later callback. */
        controllerTraceReset();
        controllerPolicy(auth, 0, 0, 0);
        controllerPolicy(auth, 100, 100, 0);
        a                                                                   = authTestControllerCreate(auth);
        ((usercontroller_tstate_t *) tunnelGetState(a))->fixed_payload_mode = kUserControllerPayloadDatagram;
        first                                                               = authTestControllerOpen(a, chain);
        controllerSend(a, first, 11, 'c', upstream);
        controllerConsumerPressure(a, first, upstream, true);
        advance(1000);
        check_resume_progress = close_in_resume = true;
        controllerConsumerPressure(a, first, upstream, false);
        require(! check_resume_progress && ! close_in_resume && ! lineIsAlive(first) && pauses == 1 && resumes == 1,
                "datagram external Resume close reentry did not settle the line");
        lineUnref(first);
        authTestControllerDestroy(a);
        advance(0);
        stats = controllerStats(auth);
        require(frames == 0 && stats.traffic.u == 0 && stats.traffic.d == 0,
                "Resume-close delivered or charged discarded datagrams");
    }
}

void authTestControllerBandwidthCases(tunnel_t *auth, tunnel_chain_t *chain, void (*advance)(unsigned))
{
    /* Two controllers share one account burst. Physical callback direction and
     * user direction remain separate, and queued bytes are uncharged. */
    controllerTraceReset();
    controllerPolicy(auth, 100, 100, 0);
    tunnel_t *a = authTestControllerCreate(auth), *b = authTestControllerCreate(auth);
    line_t   *first = authTestControllerOpen(a, chain), *second = authTestControllerOpen(b, chain);
    controllerSend(a, first, 15, 'a', true);
    require(controllerStats(auth).traffic.u == 0, "queue admission charged traffic");
    advance(0);
    require(delivered[0] == 10 && controllerStats(auth).traffic.u == 10, "100ms upload burst");
    controllerSend(b, second, 3, 'b', true);
    controllerSend(a, first, 10, 'd', false);
    require(delivered[1] == 10 && controllerStats(auth).traffic.d == 10, "independent download burst");
    advance(100);
    require(delivered[0] <= 20, "two controllers multiplied the shared burst");
    advance(100);
    require(delivered[0] == 18 && controllerStats(auth).traffic.u == 18, "shared queues lost stream bytes");
    require(frame_marks[0] == 'a' && frame_marks[1] == 'd', "first eligible turns changed direction/order");
    controllerClose(a, first);
    controllerClose(b, second);
    authTestControllerDestroy(a);
    authTestControllerDestroy(b);

    /* Consumer Pause removes fair-turn eligibility while retaining costs.
     * Resume arranges its future drain before any reentrant producer callback. */
    controllerTraceReset();
    controllerPolicy(auth, 100, 100, 0);
    advance(1000);
    a     = authTestControllerCreate(auth);
    first = authTestControllerOpen(a, chain);
    usercontrollerTunnelDownStreamPause(a, first);
    usercontrollerTunnelDownStreamPause(a, first);
    controllerSend(a, first, 20, 'p', true);
    advance(1000);
    require(delivered[0] == 0 && controllerStats(auth).traffic.u == 0, "paused consumer received/charged queued bytes");
    usercontrollerTunnelDownStreamResume(a, first);
    advance(0);
    require(delivered[0] == 10 && pauses == 1 && resumes == 0, "local and external pressure were not combined");
    close_in_resume = true;
    advance(100);
    advance(0);
    require(delivered[0] == 20 && ! lineIsAlive(first), "Resume reentry cleanup or drain progress");
    lineUnref(first);
    authTestControllerDestroy(a);

    /* Complete oversized datagrams earn credit after head activation; empty
     * datagrams retain their FIFO positions. New overflow input drops alone. */
    controllerTraceReset();
    controllerPolicy(auth, 0, 0, 0);
    controllerPolicy(auth, 1, 1, 0);
    a                                                                   = authTestControllerCreate(auth);
    ((usercontroller_tstate_t *) tunnelGetState(a))->fixed_payload_mode = kUserControllerPayloadDatagram;
    first                                                               = authTestControllerOpen(a, chain);
    controllerSend(a, first, 3, 'x', true);
    controllerSend(a, first, 0, 0, true);
    controllerSend(a, first, 1, 'y', true);
    require(controllerStats(auth).traffic.u == 0, "retained datagram charged before earned release");
    advance(1999);
    require(delivered[0] == 0 && frames == 0, "oversized datagram escaped before complete earned credit");
    advance(1);
    advance(0);
    require(frames >= 2 && frame_lengths[0] == 3 && frame_lengths[1] == 0,
            "datagram split/merge or empty FIFO position");
    advance(1000);
    require(delivered[0] == 4 && frames == 3 && frame_marks[2] == 'y', "1 byte/s datagram progress");
    usercontrollerTunnelDownStreamPause(a, first);
    controllerSend(a, first, 1, 'q', true);
    for (unsigned i = 0; i < 300; ++i)
        controllerSend(a, first, 1, 'z', true);
    usercontroller_lstate_t *ls = lineGetState(first, a);
    require(lineIsAlive(first) && trafficshaperPending(&ls->directions[0].shaper) == 256,
            "datagram overflow did not preserve bounded accepted FIFO");
    require(controllerStats(auth).traffic.u == 4, "overflow datagram charged quota");
    usercontrollerTunnelOnQuiesceRequest(a, wwLifecycleProcessShutdown());
    usercontrollerTunnelOnWorkerQuiesce(a, 0, wwLifecycleProcessShutdown());
    require(ls->directions[0].shaper.timer == NULL && ls->directions[0].shaper.continuation == NULL,
            "quiescence retained asynchronous roots");
    controllerClose(a, first);
    authTestControllerDestroy(a);
    require(controllerStats(auth).traffic.u == 4, "Finish charged discarded accepted FIFO");

    controllerDatagramPressureCases(auth, chain, advance);

    /* Streams close on overflow without charging either refused or queued
     * bytes; a quota-exhausting accepted candidate is forwarded exactly once. */
    controllerTraceReset();
    controllerPolicy(auth, 100, 0, 0);
    a     = authTestControllerCreate(auth);
    first = authTestControllerOpen(a, chain);
    usercontrollerTunnelDownStreamPause(a, first);
    controllerSend(a, first, 1024U * 1024U + 1U, 'o', true);
    require(! lineIsAlive(first) && controllerStats(auth).traffic.u == 0, "stream overflow leaked or charged input");
    lineUnref(first);
    authTestControllerDestroy(a);
    controllerPolicy(auth, 0, 0, 3);
    a     = authTestControllerCreate(auth);
    first = authTestControllerOpen(a, chain);
    controllerSend(a, first, 5, 'f', true);
    require(delivered[0] == 5 && controllerStats(auth).traffic.u == 5 && ! lineIsAlive(first),
            "quota-ending chunk must be charged and forwarded once before close");
    lineUnref(first);
    authTestControllerDestroy(a);

    /* A consumer can close during Payload, including a prepared final chunk.
     * The helper's physical reference must never grant access to dead state. */
    controllerTraceReset();
    controllerPolicy(auth, 100, 0, 0);
    advance(1000);
    a                = authTestControllerCreate(auth);
    first            = authTestControllerOpen(a, chain);
    close_in_payload = true;
    controllerSend(a, first, 11, 'r', true);
    advance(0);
    require(! lineIsAlive(first) && delivered[0] == 10 && controllerStats(auth).traffic.u == 10,
            "Payload reentry charged or forwarded discarded suffix");
    lineUnref(first);
    authTestControllerDestroy(a);

    controllerTraceReset();
    controllerPolicy(auth, 0, 0, 3);
    a               = authTestControllerCreate(auth);
    a->prev->fnFinD = reverseBorrowerFinished;
    a->next->fnFinU = finished;
    first           = lineCreate(chain->line_pools, 0);
    lineRef(first);
    user_handle_t reverse_handle = {.generation = authenticationclientUsersGeneration(auth), .user_id = 42};
    lineAddUser(first, &reverse_handle, NULL, NULL);
    tunnelDownStreamInit(a, first);
    reverse_borrower_finishes = 0;
    controllerSend(a, first, 5, 'v', false);
    require(! lineIsAlive(first) && reverse_borrower_finishes == 1 && delivered[1] == 5 &&
                controllerStats(auth).traffic.u == 5,
            "reverse quota close must hand off once and finish both sides before owner destruction");
    lineUnref(first);
    authTestControllerDestroy(a);

    controllerTraceReset();
    controllerPolicy(auth, 100, 100, 0);
    advance(1000);
    a     = authTestControllerCreate(auth);
    first = authTestControllerOpen(a, chain);
    controllerSend(a, first, 11, 'u', true);
    controllerSend(a, first, 11, 'd', false);
    ls = lineGetState(first, a);
    require(ls->directions[0].shaper.continuation != NULL && ls->directions[1].shaper.continuation != NULL,
            "both directions must track their admitted continuations");
    usercontrollerTunnelOnQuiesceRequest(a, wwLifecycleProcessShutdown());
    usercontrollerTunnelOnWorkerQuiesce(a, 0, wwLifecycleProcessShutdown());
    controllerClose(a, first);
    authTestControllerDestroy(a);
    advance(0); // Canceled tasks settle independent tokens after local state is gone.
    require(delivered[0] == 0 && delivered[1] == 0 && controllerStats(auth).traffic.u == 0,
            "quiescence delivered or charged discarded continuation work");

    controllerPolicy(auth, 100, 0, 0);
    a     = authTestControllerCreate(auth);
    first = authTestControllerOpen(a, chain);
    workerMessagesCloseAdmission(getCurrentEventWorker());
    controllerSend(a, first, 11, 'e', true);
    require(! lineIsAlive(first) && controllerStats(auth).traffic.u == 0,
            "required continuation refusal must close without charging");
    lineUnref(first);
    authTestControllerDestroy(a);
}

void authTestControllerMultiplierCases(tunnel_t *auth, tunnel_chain_t *chain, void (*advance)(unsigned), uint32_t scale)
{
    controllerTraceReset();
    controllerPolicy(auth, 10, 0, 0);
    tunnel_t *controller = authTestControllerCreate(auth);
    line_t   *line       = authTestControllerOpen(controller, chain);
    controllerSend(controller, line, 3, 'm', true);
    require(controllerStats(auth).traffic.u == 0, "multiplier applied on queue admission");
    advance(0);
    require(delivered[0] == 1 && controllerStats(auth).traffic.u == scale / kUserTrafficMultiplierScale,
            "split delivery multiplier must apply once to raw bytes");
    controllerClose(controller, line);
    line = authTestControllerOpen(controller, chain);
    controllerSend(controller, line, 1, 'n', true);
    advance(100);
    require(delivered[0] == 2 && controllerStats(auth).traffic.u == 2U * scale / kUserTrafficMultiplierScale,
            "discarded queued suffix changed multiplier carry or next handoff charge");
    controllerClose(controller, line);
    authTestControllerDestroy(controller);
}
