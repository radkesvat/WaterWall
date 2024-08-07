#include "reverse_client.h"
#include "helpers.h"
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "tunnel.h"
#include "types.h"
#include "utils/jsonutils.h"
#include "utils/mathutils.h"
#include <stddef.h>
#include <stdint.h>

static void upStream(tunnel_t *self, context_t *c)
{

    reverse_client_state_t     *state   = TSTATE(self);
    reverse_client_con_state_t *dcstate = c->line->dw_state;

    if (c->payload != NULL)
    {
        self->up->upStream(self->up, switchLine(c, dcstate->u));
    }
    else
    {
        if (c->fin)
        {
            const unsigned int tid = c->line->tid;
            context_t         *fc  = switchLine(c, dcstate->u);
            cleanup(dcstate);
            state->reverse_cons -= 1;
            LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", fc->line->tid,
                 state->threadlocal_pool[tid].unused_cons_count, state->reverse_cons);
            self->up->upStream(self->up, fc);

            initiateConnect(self, tid, false);

        }
        else if (c->est)
        {
            destroyContext(c);
        }
        else
        {
            // unexpected
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    reverse_client_state_t *state = TSTATE(self);
    uint8_t                 tid   = c->line->tid;

    if (c->payload != NULL)
    {
        reverse_client_con_state_t *ucstate = c->line->dw_state;

        if (ucstate->pair_connected)
        {
            self->dw->downStream(self->dw, switchLine(c, ucstate->d));
        }
        else
        {
            state->threadlocal_pool[tid].unused_cons_count -= 1;
            initiateConnect(self, tid, false);
            atomic_fetch_add_explicit(&(state->reverse_cons), 1, memory_order_relaxed);

            if (ucstate->idle_handle)
            {
                ucstate->idle_handle          = NULL;
                removeIdleItemByHash(ucstate->u->tid, state->starved_connections, (hash_t)(size_t) (ucstate));
            }

            ucstate->pair_connected = true;
            lockLine(ucstate->d);
            self->dw->downStream(self->dw, newInitContext(ucstate->d));
            if (! isAlive(ucstate->d))
            {
                unLockLine(ucstate->d);
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
            unLockLine(ucstate->d);
            self->dw->downStream(self->dw, switchLine(c, ucstate->d));
        }
    }
    else
    {
        reverse_client_con_state_t *ucstate = c->line->dw_state;
        if (c->fin)
        {

            if (ucstate->pair_connected)
            {
                state->reverse_cons -= 1;
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid,
                     state->threadlocal_pool[tid].unused_cons_count, state->reverse_cons);
                context_t *fc = switchLine(c, ucstate->d);
                cleanup(ucstate);
                self->dw->downStream(self->dw, fc);

                initiateConnect(self, tid, false);
            }
            else
            {
                if (ucstate->established)
                {
                    state->threadlocal_pool[tid].unused_cons_count -= 1;
                    LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid,
                         state->threadlocal_pool[tid].unused_cons_count,
                         atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
                    initiateConnect(self, tid, false);
                }
                else
                {
                    state->threadlocal_pool[tid].connecting_cons_count -= 1;
                    initiateConnect(self, tid, true);
                }

                cleanup(ucstate);
                destroyContext(c);
            }
        }
        else if (c->est)
        {
            ucstate->established = true;
            state->threadlocal_pool[tid].connecting_cons_count -= 1;
            state->threadlocal_pool[tid].unused_cons_count += 1;
            LOGI("ReverseClient: connected,    tid: %d unused: %u active: %d", tid,
                 state->threadlocal_pool[tid].unused_cons_count,
                 atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));

            initiateConnect(self, tid, false);

            ucstate->idle_handle = newIdleItem(state->starved_connections, (hash_t) (size_t)(ucstate), ucstate,
                                               onStarvedConnectionExpire, c->line->tid,
                                               kConnectionStarvationTimeOut);

            destroyContext(c);
        }
        else
        {
            // unreachable
            destroyContext(c);
        }
    }
}

static void startReverseClient(htimer_t *timer)
{
    tunnel_t *self = hevent_userdata(timer);
    for (unsigned int i = 0; i < getWorkersCount(); i++)
    {
        initiateConnect(self, i, true);
    }

    htimer_del(timer);
}

tunnel_t *newReverseClient(node_instance_context_t *instance_info)
{

    const size_t start_delay_ms = 150;

    reverse_client_state_t *state = globalMalloc(sizeof(reverse_client_state_t) + (sizeof(thread_box_t) * getWorkersCount()));
    memset(state, 0, sizeof(reverse_client_state_t) + (sizeof(thread_box_t) * getWorkersCount()));
    const cJSON *settings = instance_info->node_settings_json;

    getIntFromJsonObject((int *) &(state->min_unused_cons), settings, "minimum-unused");

    state->min_unused_cons = min(max((getWorkersCount() * (ssize_t) 8), state->min_unused_cons), 128);
    
    state->starved_connections = newIdleTable(getWorkerLoop(0));

    tunnel_t *t           = newTunnel();
    t->state              = state;
    t->upStream           = &upStream;
    t->downStream         = &downStream;
    htimer_t *start_timer = htimer_add(getWorkerLoop(0), startReverseClient, start_delay_ms, 1);
    hevent_set_userdata(start_timer, t);

    return t;
}

api_result_t apiReverseClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyReverseClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataReverseClient(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
