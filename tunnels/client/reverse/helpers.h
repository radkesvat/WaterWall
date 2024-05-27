#pragma once
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "tunnel.h"
#include "types.h"
#include "utils/mathutils.h"
#include <stdbool.h>

#define CSTATE_D(x)     ((reverse_client_con_state_t *) ((((x)->line->chains_state)[state->chain_index_d])))
#define CSTATE_U(x)     ((reverse_client_con_state_t *) ((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_D_MUT(x) ((x)->line->chains_state)[state->chain_index_d]
#define CSTATE_U_MUT(x) ((x)->line->chains_state)[self->chain_index]
enum
{
    kPreconnectDelayShort        = 10,
    kPreconnectDelayHigh         = 750,
    kConnectionStarvationTimeOut = 3000
};

static void onLinePausedU(void *cstate)
{
    pauseLineUpSide(((reverse_client_con_state_t *) cstate)->d);
}

static void onLineResumedU(void *cstate)
{
    resumeLineUpSide(((reverse_client_con_state_t *) cstate)->d);
}
static void onLinePausedD(void *cstate)
{
    pauseLineUpSide(((reverse_client_con_state_t *) cstate)->u);
}

static void onLineResumedD(void *cstate)
{
    resumeLineUpSide(((reverse_client_con_state_t *) cstate)->u);
}

static reverse_client_con_state_t *createCstate(tunnel_t *self, uint8_t tid)
{
    reverse_client_con_state_t *cstate = malloc(sizeof(reverse_client_con_state_t));
    line_t                     *up     = newLine(tid);
    line_t                     *dw     = newLine(tid);
    reserveChainStateIndex(dw); // we always take one from the down line
    setupLineDownSide(up, onLinePausedU, cstate, onLineResumedU);
    setupLineDownSide(dw, onLinePausedD, cstate, onLineResumedD);
    *cstate = (reverse_client_con_state_t){.u = up, .d = dw, .idle_handle_removed = true, .self = self};
    return cstate;
}

static void cleanup(reverse_client_con_state_t *cstate)
{
    if (! cstate->idle_handle_removed)
    {
        reverse_client_state_t *state = STATE(cstate->self);

        removeIdleItemByHash(cstate->u->tid, state->starved_connections, (hash_t) (cstate));
    }
    doneLineDownSide(cstate->u);
    doneLineDownSide(cstate->d);
    destroyLine(cstate->u);
    destroyLine(cstate->d);

    free(cstate);
}
static void doConnect(struct connect_arg *cg)
{
    tunnel_t                   *self   = cg->t;
    reverse_client_state_t     *state  = STATE(self);
    reverse_client_con_state_t *cstate = createCstate(self, cg->tid);
    free(cg);
    (cstate->u->chains_state)[self->chain_index]    = cstate;
    (cstate->d->chains_state)[state->chain_index_d] = cstate;
    context_t *hello_data_ctx                       = newContext(cstate->u);
    self->up->upStream(self->up, newInitContext(cstate->u));

    if (! isAlive(cstate->u))
    {
        destroyContext(hello_data_ctx);
        return;
    }
    hello_data_ctx->first   = true;
    hello_data_ctx->payload = popBuffer(getContextBufferPool(hello_data_ctx));
    setLen(hello_data_ctx->payload, 1);
    writeUI8(hello_data_ctx->payload, 0xFF);
    self->up->upStream(self->up, hello_data_ctx);
}

static void connectTimerFinished(htimer_t *timer)
{
    doConnect(hevent_userdata(timer));
    htimer_del(timer);
}
static void beforeConnect(hevent_t *ev)
{
    struct connect_arg *cg            = hevent_userdata(ev);
    htimer_t           *connect_timer = htimer_add(loops[cg->tid], connectTimerFinished, cg->delay, 1);
    if (connect_timer)
    {
        hevent_set_userdata(connect_timer, cg);
    }
    else
    {
        doConnect(cg);
    }
}

static void initiateConnect(tunnel_t *self, uint8_t tid, bool delay)
{
    reverse_client_state_t *state = STATE(self);

    if (state->unused_cons[tid] >= state->min_unused_cons)
    {
        return;
    }
    // bool more_delay = state->unused_cons[tid] <= 0;
    // state->unused_cons[tid] += 1;

    // int tid = 0;
    // if (workers_count > 0)
    // {
    //     tid = atomic_fetch_add_explicit(&(state->round_index), 1, memory_order_relaxed);

    //     if (tid >= workers_count)
    //     {
    //         atomic_store_explicit(&(state->round_index), 0, memory_order_relaxed);
    //         tid = 0;
    //     }
    // }

    hloop_t *worker_loop = loops[tid];

    hevent_t            ev = {.loop = worker_loop, .cb = beforeConnect};
    struct connect_arg *cg = malloc(sizeof(struct connect_arg));
    ev.userdata            = cg;
    cg->t                  = self;
    cg->tid                = tid;
    cg->delay              = delay ? kPreconnectDelayHigh : kPreconnectDelayShort;

    hloop_post_event(worker_loop, &ev);
}
static void onStarvedConnectionExpire(idle_item_t *idle_con)
{
    LOGW("ReverseClient: onStarvedConnectionExpire");
    reverse_client_con_state_t *cstate = idle_con->userdata;
    tunnel_t                   *self   = cstate->self;
    cstate->idle_handle_removed        = true;
    // old connection will expire anyway...
    initiateConnect(self, cstate->u->tid, false);
}
