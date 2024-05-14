#include "reverse_client.h"
#include "buffer_pool.h"
#include "helpers.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "types.h"
#include "utils/jsonutils.h"

static void upStream(tunnel_t *self, context_t *c)
{

    reverse_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        reverse_client_con_state_t *dcstate = CSTATE_D(c);
        if (! dcstate->first_sent_u)
        {
            dcstate->first_sent_u = true;
            c->first              = true;
        }
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
            const unsigned int old_reverse_cons =
                atomic_fetch_add_explicit(&(state->reverse_cons), -1, memory_order_relaxed);
            LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", fc->line->tid, state->unused_cons[tid],
                 old_reverse_cons - 1);
            self->up->upStream(self->up, fc);
        }
        else if (c->est)
        {
            destroyContext(c);
        }
        else
        {
            assert(false); // unexpected
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
            if (! ucstate->first_sent_d)
            {
                if (state->unused_cons[tid] > 0)
                {
                    state->unused_cons[tid] -= 1;
                }
                atomic_fetch_add_explicit(&(state->reverse_cons), 1, memory_order_relaxed);
                initiateConnect(self, tid, false);
                context_t *turned = switchLine(c, ucstate->d);
                if (! isAlive(ucstate->d))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                ucstate->first_sent_d = true;
                turned->first         = true;
                self->dw->downStream(self->dw, turned);
            }
            else
            {
                self->dw->downStream(self->dw, switchLine(c, ucstate->d));
            }
        }
        else
        {

            // first byte is 0xFF a signal from reverse server
            uint8_t check = 0x0;
            readUI8(c->payload, &check);
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
            shiftr(c->payload, 1);
            state->unused_cons[tid] += 1;
            LOGI("ReverseClient: connected,    tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                 atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
            ucstate->pair_connected = true;
            self->dw->downStream(self->dw, newInitContext(ucstate->d));

            reuseContextBuffer(c);
            destroyContext(c);
            return;
        }
    }
    else
    {

        if (c->fin)
        {
            reverse_client_con_state_t *ucstate              = CSTATE_U(c);
            CSTATE_U_MUT(c)                                  = NULL;
            (ucstate->d->chains_state)[state->chain_index_d] = NULL;

            if (ucstate->pair_connected)
            {
                const unsigned int old_reverse_cons =
                    atomic_fetch_add_explicit(&(state->reverse_cons), -1, memory_order_relaxed);
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                     old_reverse_cons - 1);
                context_t *fc = switchLine(c, ucstate->d);
                cleanup(ucstate);
                self->dw->downStream(self->dw, fc);
            }
            else
            {
                cleanup(ucstate);
                if (state->unused_cons[tid] > 0)
                {
                    state->unused_cons[tid] -= 1;
                }
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                     atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
                initiateConnect(self, tid, true);

                destroyContext(c);
            }
        }
        else if (c->est)
        {
            CSTATE_U(c)->established = true;

            context_t *hello_data_ctx = newContextFrom(c);
            hello_data_ctx->payload   = popBuffer(getContextBufferPool(c));
            setLen(hello_data_ctx->payload, 1);
            writeUI8(hello_data_ctx->payload, 0xFF);
            self->up->upStream(self->up, hello_data_ctx);

            destroyContext(c);
        }
        else
        {
            assert(false); // unexpected
        }
    }
}

static void startReverseClient(htimer_t *timer)
{
    tunnel_t               *self  = hevent_userdata(timer);
    reverse_client_state_t *state = STATE(self);
    for (int i = 0; i < workers_count; i++)
    {
        const int cpt = state->connection_per_thread;

        for (size_t ci = 0; ci < cpt; ci++)
        {
            initiateConnect(self, i, true);
        }
    }

    htimer_del(timer);
}
tunnel_t *newReverseClient(node_instance_context_t *instance_info)
{

    const size_t start_delay_ms = 150;

    reverse_client_state_t *state = malloc(sizeof(reverse_client_state_t) + (sizeof(atomic_uint) * workers_count));
    memset(state, 0, sizeof(reverse_client_state_t) + (sizeof(atomic_uint) * workers_count));
    const cJSON *settings = instance_info->node_settings_json;

    getIntFromJsonObject(&(state->min_unused_cons), settings, "minimum-unused");

    // int total = max(16, state->cons_forward);
    // int total = max(1, state->cons_forward);
    state->min_unused_cons       = 1;
    state->connection_per_thread = 1;

    // we are always the first line creator so its easy to get the positon independent index here
    line_t *l            = newLine(0);
    int     index        = reserveChainStateIndex(l);
    state->chain_index_d = index;
    destroyLine(l);

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
tunnel_metadata_t getMetadataReverseClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}