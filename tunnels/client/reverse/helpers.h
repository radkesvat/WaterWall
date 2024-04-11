#pragma once
#include "types.h"
#include "loggers/network_logger.h"

#define STATE(x) ((reverse_client_state_t *)((x)->state))
#define CSTATE_D(x) ((reverse_client_con_state_t *)((((x)->line->chains_state)[state->chain_index_pi])))
#define CSTATE_U(x) ((reverse_client_con_state_t *)((((x)->line->chains_state)[state->chain_index_pi])))
#define CSTATE_D_MUT(x) ((x)->line->chains_state)[state->chain_index_pi]
#define CSTATE_U_MUT(x) ((x)->line->chains_state)[state->chain_index_pi]
#define ISALIVE(x) (((((x)->line->chains_state)[state->chain_index_pi])) != NULL)
#define PRECONNECT_DELAY_SHORT 10
#define PRECONNECT_DELAY_HIGH 1500
#undef max
#undef min
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline size_t max(size_t x, size_t y) { return (((x) < (y)) ? (y) : (x)); }

static reverse_client_con_state_t *create_cstate(int tid)
{
    reverse_client_con_state_t *cstate = malloc(sizeof(reverse_client_con_state_t));
    memset(cstate, 0, sizeof(reverse_client_con_state_t));

    line_t *up = newLine(tid);
    line_t *dw = newLine(tid);
    cstate->u = up;
    cstate->d = dw;

    return cstate;
}

static void destroy_cstate(reverse_client_con_state_t *cstate)
{
    destroyLine(cstate->u);
    destroyLine(cstate->d);

    free(cstate);
}
static void do_connect(struct connect_arg *cg)
{
    tunnel_t *self = cg->t;
    reverse_client_state_t *state = STATE(self);
    reverse_client_con_state_t *cstate = create_cstate(cg->tid);
    free(cg);
    (cstate->u->chains_state)[state->chain_index_pi] = cstate;
    (cstate->d->chains_state)[state->chain_index_pi] = cstate;
    self->up->upStream(self->up, newInitContext(cstate->u));
}

static void connect_timer_finished(htimer_t *timer)
{
    do_connect(hevent_userdata(timer));
    htimer_del(timer);
}
static void before_connect(hevent_t *ev)
{
    struct connect_arg *cg = hevent_userdata(ev);
    htimer_t *connect_timer = htimer_add(loops[cg->tid], connect_timer_finished, cg->delay, 1);
    hevent_set_userdata(connect_timer, cg);
}

static void initiateConnect(tunnel_t *t, int tid)
{
    if (STATE(t)->unused_cons[tid] >= STATE(t)->connection_per_thread)
        return;
    bool more_delay = STATE(t)->unused_cons[tid] <= 0;
    // STATE(t)->unused_cons[tid] += 1;

    // int tid = 0;
    // if (threads_count > 0)
    // {
    //     tid = atomic_fetch_add_explicit(&(STATE(t)->round_index), 1, memory_order_relaxed);

    //     if (tid >= threads_count)
    //     {
    //         atomic_store_explicit(&(STATE(t)->round_index), 0, memory_order_relaxed);
    //         tid = 0;
    //     }
    // }

    hloop_t *worker_loop = loops[tid];
    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = worker_loop;
    ev.cb = before_connect;
    struct connect_arg *cg = malloc(sizeof(struct connect_arg));
    cg->t = t;
    cg->tid = tid;
    cg->delay = more_delay?PRECONNECT_DELAY_HIGH:PRECONNECT_DELAY_SHORT;
    ev.userdata = cg;
    hloop_post_event(worker_loop, &ev);
}