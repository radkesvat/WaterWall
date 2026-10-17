/* Real UserController payload and idle-sweep paths for authentication_sync_test.
 * The fixture head owns each normal line; UserController borrows it. */
#include "UserController/structure.h"
#include "authentication_sync_peer.h"
#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

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
    discard t;
    lineReuseBuffer(l, b);
}

tunnel_t *authTestControllerCreate(tunnel_t *auth)
{
    tunnel_t *controller = tunnelCreate(NULL, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t));
    tunnel_t *head = tunnelCreate(NULL, 0, 0), *tail = tunnelCreate(NULL, 0, 0);
    require(controller != NULL && head != NULL && tail != NULL, "controller fixture allocation");
    head->fnFinD           = finished;
    tail->fnInitU          = initialized;
    tail->fnFinU           = initialized;
    tail->fnPayloadU       = consumed;
    controller->fnInitU    = usercontrollerTunnelUpStreamInit;
    controller->fnFinU     = usercontrollerTunnelUpStreamFinish;
    controller->fnPayloadU = usercontrollerTunnelUpStreamPayload;
    tunnelBind(head, controller);
    tunnelBind(controller, tail);
    usercontroller_tstate_t *ts = tunnelGetState(controller);
    ts->auth_client_tunnel      = auth;
    ts->worker_count            = 1;
    ts->worker_states           = memoryAllocateZero(sizeof(*ts->worker_states));
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
    require(ts->worker_states[0].line_count == 0, "controller retained line references");
    tunnelDestroy(controller->prev);
    tunnelDestroy(controller->next);
    usercontrollerTunnelDestroy(controller, wwLifecycleProcessShutdown());
}
