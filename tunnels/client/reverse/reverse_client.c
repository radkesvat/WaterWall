#include "reverse_client.h"
#include "helpers.h"
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "types.h"
#include "utils/jsonutils.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

static void upStream(tunnel_t *self, context_t *c)
{

    reverse_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        reverse_client_con_state_t *dcstate = CSTATE_D(c);
        self->up->upStream(self->up, switchLine(c, dcstate->u));
    }
    else
    {
        if (c->fin)
        {
            const unsigned int          tid               = c->line->tid;
            reverse_client_con_state_t *dcstate           = CSTATE_D(c);
            CSTATE_D_MUT(c)                               = NULL;
            (dcstate->u->chains_state)[self->chain_index] = NULL;
            context_t *fc                                 = switchLine(c, dcstate->u);
            cleanup(dcstate);
            state->reverse_cons -= 1;
            LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", fc->line->tid, state->unused_cons[tid],
                 state->reverse_cons);
            self->up->upStream(self->up, fc);
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
    reverse_client_state_t *state = STATE(self);
    uint8_t                 tid   = c->line->tid;

    if (c->payload != NULL)
    {
        reverse_client_con_state_t *ucstate = CSTATE_U(c);

        if (ucstate->pair_connected)
        {
            self->dw->downStream(self->dw, switchLine(c, ucstate->d));
        }
        else
        {
            while (true)
            {

                if (ucstate->handshaked)
                {
                    if (state->unused_cons[tid] > 0)
                    {
                        state->unused_cons[tid] -= 1;
                    }
                    initiateConnect(self, tid, false);
                    atomic_fetch_add_explicit(&(state->reverse_cons), 1, memory_order_relaxed);

                    ucstate->pair_connected = true;
                    lockLine(ucstate->d);
                    self->dw->downStream(self->dw, newInitContext(ucstate->d));
                    if (! isAlive(ucstate->d))
                    {
                        unLockLine(ucstate->d);
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                    unLockLine(ucstate->d);
                    ucstate->first_sent_d = true;
                    context_t *turned     = switchLine(c, ucstate->d);
                    turned->first         = true;
                    self->dw->downStream(self->dw, turned);
                }
                else
                {
                    // first byte is 0xFF a signal from reverse server
                    uint8_t check = 0x0;
                    readUI8(c->payload, &check);
                    shiftr(c->payload, 1);
                    if (check != (unsigned char) 0xFF)
                    {

                        reuseContextBuffer(c);
                        CSTATE_U_MUT(c)                                  = NULL;
                        (ucstate->d->chains_state)[state->chain_index_d] = NULL;
                        cleanup(ucstate);
                        self->up->upStream(self->up, newFinContextFrom(c));
                        destroyContext(c);
                        return;
                    }
                    ucstate->handshaked = true;
                    state->unused_cons[tid] += 1;
                    LOGI("ReverseClient: connected,    tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                         atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));

                    if (bufLen(c->payload) > 0)
                    {
                        continue;
                    }
                    reuseContextBuffer(c);
                    destroyContext(c);
                }
                return;
            }
        }
    }
    else
    {
        reverse_client_con_state_t *ucstate = CSTATE_U(c);
        if (c->fin)
        {
            CSTATE_U_MUT(c)                                  = NULL;
            (ucstate->d->chains_state)[state->chain_index_d] = NULL;

            if (ucstate->pair_connected)
            {
                state->reverse_cons -= 1;
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                     state->reverse_cons);
                context_t *fc = switchLine(c, ucstate->d);
                cleanup(ucstate);
                self->dw->downStream(self->dw, fc);
            }
            else
            {
                if (ucstate->handshaked)
                {
                    if (state->unused_cons[tid] > 0)
                    {
                        state->unused_cons[tid] -= 1;
                    }
                    LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                         atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
                }
                cleanup(ucstate);
                initiateConnect(self, tid, true);
                destroyContext(c);
            }
        }
        else if (c->est)
        {
            ucstate->established = true;
            initiateConnect(self, tid, false);

            idle_item_t *con_idle_item = newIdleItem(state->starved_connections, (hash_t) (ucstate), ucstate,
                                                     onStarvedConnectionExpire, c->line->tid, kConnectionStarvationTimeOut);
            (void)con_idle_item;
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
    for (unsigned int i = 0; i < workers_count; i++)
    {
        initiateConnect(self, i, true);
    }

    htimer_del(timer);
}
tunnel_t *newReverseClient(node_instance_context_t *instance_info)
{

    const size_t start_delay_ms = 150;

    reverse_client_state_t *state = malloc(sizeof(reverse_client_state_t) + (sizeof(atomic_uint) * workers_count));
    memset(state, 0, sizeof(reverse_client_state_t) + (sizeof(atomic_uint) * workers_count));
    const cJSON *settings = instance_info->node_settings_json;

    getIntFromJsonObject((int *) &(state->min_unused_cons), settings, "minimum-unused");

    state->min_unused_cons = min(max((workers_count * (ssize_t) 8), state->min_unused_cons), 128);

    // we are always the first line creator so its easy to get the positon independent index here
    line_t *l            = newLine(0);
    int     index        = reserveChainStateIndex(l);
    state->chain_index_d = index;
    destroyLine(l);

    state->starved_connections = newIdleTable(loops[0]);

    tunnel_t *t           = newTunnel();
    t->state              = state;
    t->upStream           = &upStream;
    t->downStream         = &downStream;
    htimer_t *start_timer = htimer_add(loops[0], startReverseClient, start_delay_ms, 1);
    hevent_set_userdata(start_timer, t);

    atomic_thread_fence(memory_order_release);

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
