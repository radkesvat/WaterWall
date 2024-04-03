#include "reverse_client.h"
#include "loggers/network_logger.h"
#include "types.h"
#include "helpers.h"

static inline void upStream(tunnel_t *self, context_t *c)
{

    reverse_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        reverse_client_con_state_t *dcstate = CSTATE_D(c);
        if (!dcstate->first_sent)
        {
            dcstate->first_sent = true;
            c->first = true;
        }
        self->up->upStream(self->up, switchLine(c, dcstate->u));
    }
    else
    {

        if (c->fin)
        {
            unsigned int tid = c->line->tid;
            reverse_client_con_state_t *dcstate = CSTATE_D(c);
            CSTATE_D_MUT(c) = NULL;
            (dcstate->u->chains_state)[state->chain_index_pi] = NULL;
            context_t *fc = switchLine(c, dcstate->u);
            destroy_cstate(dcstate);
            self->up->upStream(self->up, fc);
            unsigned int rcs = atomic_fetch_add_explicit(&(STATE(self)->reverse_cons), -1, memory_order_relaxed);
            LOGD("ReverseClient: disconnected, unused: %d active: %d", STATE(self)->unused_cons, rcs - 1);
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

static inline void downStream(tunnel_t *self, context_t *c)
{
    reverse_client_state_t *state = STATE(self);
    unsigned int tid = c->line->tid;

    if (c->payload != NULL)
    {
        reverse_client_con_state_t *ucstate = CSTATE_U(c);

        if (ucstate->pair_connected)
        {
            self->dw->downStream(self->dw, switchLine(c, CSTATE_U(c)->d));
        }
        else
        {
            self->dw->downStream(self->dw, newInitContext(ucstate->d));
            if (!ISALIVE(c))
            {
                DISCARD_CONTEXT(c);
                destroyContext(c);
                return;
            }
            ucstate->pair_connected = true;
            c->first = true;
            atomic_fetch_add_explicit(&(STATE(self)->unused_cons), -1, memory_order_relaxed);
            atomic_fetch_add_explicit(&(STATE(self)->reverse_cons), 1, memory_order_relaxed);
            self->dw->downStream(self->dw, switchLine(c, CSTATE_U(c)->d));
            initiateConnect(self);
        }
    }
    else
    {

        if (c->fin)
        {
            reverse_client_con_state_t *ucstate = CSTATE_U(c);
            CSTATE_U_MUT(c) = NULL;
            (ucstate->d->chains_state)[state->chain_index_pi] = NULL;
            if (ucstate->pair_connected)
            {
                atomic_fetch_add_explicit(&(STATE(self)->reverse_cons), -1, memory_order_relaxed);
                context_t *fc = switchLine(c, ucstate->d);
                destroy_cstate(ucstate);
                self->dw->downStream(self->dw, fc);
            }
            else
            {
                if (ucstate->established)
                {
                    destroy_cstate(ucstate);
                    atomic_fetch_add_explicit(&(STATE(self)->unused_cons), -1, memory_order_relaxed);
                }
                else
                    destroy_cstate(ucstate);
                destroyContext(c);

                initiateConnect(self);
            }

            LOGD("ReverseClient: disconnected, unused: %d active: %d", STATE(self)->unused_cons, STATE(self)->reverse_cons);
        }
        else if (c->est)
        {
            CSTATE_U(c)->established = true;
            atomic_fetch_add_explicit(&(STATE(self)->unused_cons), 1, memory_order_relaxed);
            LOGI("ReverseClient: connected,    unused: %d active: %d", STATE(self)->unused_cons, STATE(self)->reverse_cons);
            destroyContext(c);
            initiateConnect(self);
        }
        else
        {
            assert(false); // unexpected
        }
    }
}
static void reverseClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void reverseClientPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void reverseClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void reverseClientPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

static void start_reverse_celint(htimer_t *timer)
{
    tunnel_t *t = hevent_userdata(timer);
    for (int i = 0; i < threads_count; i++)
    {
        const int cpt = STATE(t)->connection_per_thread;

        for (size_t ci = 0; ci < cpt; ci++)
        {
            initiateConnect(t);
        }
    }

    htimer_del(timer);
}
tunnel_t *newReverseClient(node_instance_context_t *instance_info)
{

    const size_t start_delay_ms = 150;

    reverse_client_state_t *state = malloc(sizeof(reverse_client_state_t));
    memset(state, 0, sizeof(reverse_client_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    getIntFromJsonObject(&(state->min_unused_cons), settings, "minimum-unused");

    // int total = max(16, state->cons_forward);
    // int total = max(1, state->cons_forward);
    state->min_unused_cons = min(max(threads_count * 2, state->min_unused_cons), 128);
    state->connection_per_thread = state->min_unused_cons / threads_count;

    // we are always the first line creator so its easy to get the positon independent index here
    line_t *l = newLine(0);
    int index = reserveChainStateIndex(l);
    state->chain_index_pi = index;
    destroyLine(l);

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &reverseClientUpStream;
    t->packetUpStream = &reverseClientPacketUpStream;
    t->downStream = &reverseClientDownStream;
    t->packetDownStream = &reverseClientPacketDownStream;

    htimer_t *start_timer = htimer_add(loops[0], start_reverse_celint, start_delay_ms, 1);
    hevent_set_userdata(start_timer, t);

    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiReverseClient(tunnel_t *self, char *msg)
{
    LOGE("reverseClient API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyReverseClient(tunnel_t *self)
{
    LOGE("reverseClient DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataReverseClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = TFLAG_ROUTE_STARTER};
}