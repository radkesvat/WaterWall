#pragma once
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "tunnel.h"
#include "types.h"
#include <stdbool.h>

enum
{
    kHandShakeByte               = 0xFF,
    kHandShakeLength             = 96,
    kPreconnectDelayShort        = 10,
    kPreconnectDelayLong         = 750,
    kConnectionStarvationTimeOut = 45000
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
    reverse_client_con_state_t *cstate = globalMalloc(sizeof(reverse_client_con_state_t));
    line_t                     *up     = newLine(tid);
    line_t                     *dw     = newLine(tid);
    // reserveChainStateIndex(dw); // we always take one from the down line
    setupLineDownSide(up, onLinePausedU, cstate, onLineResumedU);
    setupLineDownSide(dw, onLinePausedD, cstate, onLineResumedD);
    *cstate = (reverse_client_con_state_t){.u = up, .d = dw, .idle_handle = NULL, .self = self};
    return cstate;
}

static void cleanup(reverse_client_con_state_t *cstate)
{
    if (cstate->idle_handle)
    {
        reverse_client_state_t *state = TSTATE(cstate->self);
        removeIdleItemByHash(cstate->u->tid, state->starved_connections, (hash_t) (size_t) (cstate));
    }
    doneLineDownSide(cstate->u);
    doneLineDownSide(cstate->d);
    destroyLine(cstate->u);
    destroyLine(cstate->d);

    globalFree(cstate);
}
static void doConnect(struct connect_arg *cg)
{
    tunnel_t *self = cg->t;
    // reverse_client_state_t     *state  = TSTATE(self);
    reverse_client_con_state_t *cstate = createCstate(self, cg->tid);
    globalFree(cg);
    context_t *hello_data_ctx = newContext(cstate->u);
    self->up->upStream(self->up, newInitContext(cstate->u));

    if (! isAlive(cstate->u))
    {
        destroyContext(hello_data_ctx);
        return;
    }
    hello_data_ctx->payload = popBuffer(getContextBufferPool(hello_data_ctx));
    setLen(hello_data_ctx->payload, kHandShakeLength);
    memset(rawBufMut(hello_data_ctx->payload), kHandShakeByte, kHandShakeLength);
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
    htimer_t           *connect_timer = htimer_add(WORKERS[cg->tid].loop, connectTimerFinished, cg->delay, 1);
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
    reverse_client_state_t *state = TSTATE(self);

    if (state->threadlocal_pool[tid].unused_cons_count + state->threadlocal_pool[tid].connecting_cons_count >=
        state->min_unused_cons)
    {
        return;
    }
    state->threadlocal_pool[tid].connecting_cons_count += 1;
    // bool more_delay = state->threadlocal_pool[tid].unused_cons_count <= 0;
    // state->threadlocal_pool[tid].unused_cons_count += 1;

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

    hloop_t *worker_loop = WORKERS[tid].loop;

    hevent_t            ev = {.loop = worker_loop, .cb = beforeConnect};
    struct connect_arg *cg = globalMalloc(sizeof(struct connect_arg));
    ev.userdata            = cg;
    cg->t                  = self;
    cg->tid                = tid;
    cg->delay              = delay ? kPreconnectDelayLong : kPreconnectDelayShort;

    hloop_post_event(worker_loop, &ev);
}

static void onStarvedConnectionExpire(idle_item_t *idle_con)
{
    reverse_client_con_state_t *cstate = idle_con->userdata;
    tunnel_t                   *self   = cstate->self;
    reverse_client_state_t     *state  = TSTATE(self);
    if (cstate->idle_handle == NULL)
    {
        // this can happen if we are unlucky and 2 events are passed to eventloop in
        //  a bad order, first connection to peer succeeds and also the starvation cb call
        //  is already in the queue
        assert(cstate->pair_connected);
        return;
    }

    assert(! cstate->pair_connected);

    state->threadlocal_pool[cstate->u->tid].unused_cons_count -= 1;
    LOGW("ReverseClient: a idle connection detected and closed");

    cstate->idle_handle = NULL;
    initiateConnect(self, cstate->u->tid, false);

    context_t *fc = newFinContext(cstate->u);
    cleanup(cstate);
    self->up->upStream(self->up, fc);
}
