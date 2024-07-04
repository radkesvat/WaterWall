#pragma once
#include "loggers/network_logger.h"
#include "types.h"
#include "utils/mathutils.h"

enum
{
    kPreconnectDelayShort = 10,
    kPreconnectDelayLong  = 750
};

static void addConnection(thread_box_t *box, preconnect_client_con_state_t *con)
{
    con->next      = box->root.next;
    box->root.next = con;
    con->prev      = &box->root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->length += 1;
}
static void removeConnection(thread_box_t *box, preconnect_client_con_state_t *con)
{

    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->length -= 1;
}

static preconnect_client_con_state_t *createCstate(uint8_t tid)
{
    preconnect_client_con_state_t *cstate = wwmGlobalMalloc(sizeof(preconnect_client_con_state_t));
    memset(cstate, 0, sizeof(preconnect_client_con_state_t));
    cstate->u = newLine(tid);
    return cstate;
}

static void destroyCstate(preconnect_client_con_state_t *cstate)
{
    destroyLine(cstate->u);
    wwmGlobalFree(cstate);
}
static void doConnect(struct connect_arg *cg)
{
    tunnel_t                      *self   = cg->t;
    preconnect_client_con_state_t *cstate = createCstate(cg->tid);
    wwmGlobalFree(cg);
    LSTATE_MUT(cstate->u) = cstate;
    self->up->upStream(self->up, newInitContext(cstate->u));
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

static void initiateConnect(tunnel_t *self, bool delay)
{
    preconnect_client_state_t *state = TSTATE(self);

    if (state->unused_cons >= state->min_unused_cons)
    {
        return;
    }

    uint8_t tid = 0;
    if (workers_count > 0)
    {
        tid = atomic_fetch_add_explicit(&(state->round_index), 1, memory_order_relaxed);

        if (tid >= workers_count)
        {
            atomic_store_explicit(&(state->round_index), 0, memory_order_relaxed);
            tid = 0;
        }
    }

    hloop_t *worker_loop = loops[tid];

    hevent_t            ev = {.loop = worker_loop, .cb = beforeConnect};
    struct connect_arg *cg = wwmGlobalMalloc(sizeof(struct connect_arg));
    ev.userdata            = cg;
    cg->t                  = self;
    cg->tid                = tid;
    cg->delay              = delay ? kPreconnectDelayLong : kPreconnectDelayShort;

    hloop_post_event(worker_loop, &ev);
}
