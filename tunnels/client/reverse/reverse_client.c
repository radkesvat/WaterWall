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
        if (!dcstate->first_sent_u)
        {
            dcstate->first_sent_u = true;
            c->first = true;
        }
        self->up->upStream(self->up, switchLine(c, dcstate->u));
    }
    else
    {

        if (c->fin)
        {
            const unsigned int tid = c->line->tid;
            reverse_client_con_state_t *dcstate = CSTATE_D(c);
            CSTATE_D_MUT(c) = NULL;
            (dcstate->u->chains_state)[state->chain_index_pi] = NULL;
            context_t *fc = switchLine(c, dcstate->u);
            destroy_cstate(dcstate);
            const unsigned int old_reverse_cons = atomic_fetch_add_explicit(&(state->reverse_cons), -1, memory_order_relaxed);
            LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", fc->line->tid, state->unused_cons[tid], old_reverse_cons - 1);
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

static inline void downStream(tunnel_t *self, context_t *c)
{
    reverse_client_state_t *state = STATE(self);
    unsigned int tid = c->line->tid;

    if (c->payload != NULL)
    {
        reverse_client_con_state_t *ucstate = CSTATE_U(c);

        if (ucstate->pair_connected)
        {
            if (!ucstate->first_sent_d)
            {
                ucstate->first_sent_d = true;
                context_t *turned = switchLine(c, ucstate->d);
                turned->first = true;
                self->dw->downStream(self->dw, turned);
            }
            else
                self->dw->downStream(self->dw, switchLine(c, ucstate->d));
        }
        else
        {
            ucstate->pair_connected = true;
            if (state->unused_cons[tid] > 0)
                state->unused_cons[tid] -= 1;
            atomic_fetch_add_explicit(&(state->reverse_cons), 1, memory_order_relaxed);
            self->dw->downStream(self->dw, newInitContext(ucstate->d));
            
            if (CSTATE_U(c) == NULL)
            {
                reuseBuffer(buffer_pools[c->line->tid], c->payload);
                c->payload = NULL;
                destroyContext(c);
                return;
            }

            // first byte is 0xFF a signal from reverse server
            uint8_t check = 0x0;
            readUI8(c->payload, &check);
            assert(check == (unsigned char)0xFF);
            shiftr(c->payload, 1);
            if (bufLen(c->payload) <= 0)
            {
                initiateConnect(self, tid);
                reuseBuffer(buffer_pools[c->line->tid], c->payload);
                c->payload = NULL;
                destroyContext(c);
                return;
            }
            else
            {
                ucstate->first_sent_d = true;
                c->first = true;
                self->dw->downStream(self->dw, switchLine(c, ucstate->d));
                initiateConnect(self, tid);
            }
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
                const unsigned int old_reverse_cons = atomic_fetch_add_explicit(&(state->reverse_cons), -1, memory_order_relaxed);
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid], old_reverse_cons - 1);
                context_t *fc = switchLine(c, ucstate->d);
                destroy_cstate(ucstate);
                self->dw->downStream(self->dw, fc);
            }
            else
            {
                destroy_cstate(ucstate);
                if (state->unused_cons[tid] > 0)
                    state->unused_cons[tid] -= 1;
                LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                     atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
                initiateConnect(self, tid);

                destroyContext(c);
            }
        }
        else if (c->est)
        {
            CSTATE_U(c)->established = true;
            state->unused_cons[tid] += 1;
            LOGI("ReverseClient: connected,    tid: %d unused: %u active: %d", tid, state->unused_cons[tid],
                 atomic_load_explicit(&(state->reverse_cons), memory_order_relaxed));
            destroyContext(c);
            initiateConnect(self, tid);
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
    for (int i = 0; i < workers_count; i++)
    {
        const int cpt = STATE(t)->connection_per_thread;

        for (size_t ci = 0; ci < cpt; ci++)
        {
            initiateConnect(t, i);
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
    state->min_unused_cons = min(max(workers_count * 4, state->min_unused_cons), 128);
    state->connection_per_thread = min(4, state->min_unused_cons / workers_count);

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
    (void)(self); (void)(msg); return (api_result_t){0}; // TODO
}

tunnel_t *destroyReverseClient(tunnel_t *self)
{
    return NULL;
}
tunnel_metadata_t getMetadataReverseClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = TFLAG_ROUTE_STARTER};
}