#pragma once
#include "types.h"
#include "loggers/network_logger.h"

#define STATE(x) ((preconnect_client_state_t *)((x)->state))
#define CSTATE(x) ((preconnect_client_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (((((x)->line->chains_state)[self->chain_index])) != NULL)
#define PRECONNECT_DELAY 100
#undef max
#undef min
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline size_t max(size_t x, size_t y) { return (((x) < (y)) ? (y) : (x)); }

static void add_connection(thread_box_t *box,
                           preconnect_client_con_state_t *con)
{
    con->next = box->root.next;
    box->root.next = con;
    con->prev = &box->root;
    if (con->next)
    {
        con->next->prev = con;
    }
    box->length += 1;
}
static void remove_connection(thread_box_t *box, preconnect_client_con_state_t *con)
{

    con->prev->next = con->next;
    if (con->next)
    {
        con->next->prev = con->prev;
    }
    box->length -= 1;
}

static preconnect_client_con_state_t *create_cstate(int tid)
{
    preconnect_client_con_state_t *cstate = malloc(sizeof(preconnect_client_con_state_t));
    memset(cstate, 0, sizeof(preconnect_client_con_state_t));
    cstate->u = newLine(tid);

    return cstate;
}

static void destroy_cstate(preconnect_client_con_state_t *cstate)
{
    destroyLine(cstate->u);

    free(cstate);
}
static void do_connect(struct connect_arg *cg)
{
    tunnel_t *self = cg->t;
    preconnect_client_state_t *state = STATE(self);
    preconnect_client_con_state_t *cstate = create_cstate(cg->tid);
    free(cg);
    (cstate->u->chains_state)[self->chain_index] = cstate;
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
    htimer_t *connect_timer = htimer_add(loops[cg->tid], connect_timer_finished, PRECONNECT_DELAY, 1);
    hevent_set_userdata(connect_timer, cg);
}

static void initiateConnect(tunnel_t *t)
{
    if (STATE(t)->unused_cons >= STATE(t)->min_unused_cons)
        return;

    int tid = 0;
    if (workers_count > 0)
    {
        tid = atomic_fetch_add_explicit(&(STATE(t)->round_index), 1, memory_order_relaxed);

        if (tid >= workers_count)
        {
            atomic_store_explicit(&(STATE(t)->round_index), 0, memory_order_relaxed);
            tid = 0;
        }
    }

    hloop_t *worker_loop = loops[tid];
    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = worker_loop;
    ev.cb = before_connect;
    struct connect_arg *cg = malloc(sizeof(struct connect_arg));
    cg->t = t;
    cg->tid = tid;
    ev.userdata = cg;
    hloop_post_event(worker_loop, &ev);
}