#include "preconnect_client.h"
#include "managers/node_manager.h"
#include "loggers/network_logger.h"
#include "types.h"
#include "helpers.h"

static inline void upStream(tunnel_t *self, context_t *c)
{

    preconnect_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        preconnect_client_con_state_t *cstate = CSTATE(c);
        switch (cstate->mode)
        {

        case connected_direct:
            self->up->upStream(self->up, c);
            break;

        case connected_pair:
            self->up->upStream(self->up, switchLine(c, cstate->u));
            break;
        case notconnected:
        default:
            LOGF("PreConnectClient: invalid value of connection state (memory error?)");
            exit(1);

            break;
        }
    }
    else
    {
        const unsigned int tid = c->line->tid;
        thread_box_t *this_tb = &(state->threads[tid]);
        if (c->init)
        {

            if (this_tb->length > 0)
            {
                atomic_fetch_add_explicit(&(state->unused_cons), -1, memory_order_relaxed);
                atomic_fetch_add_explicit(&(state->active_cons), 1, memory_order_relaxed);

                preconnect_client_con_state_t *ucon = this_tb->root.next;
                remove_connection(this_tb, ucon);
                ucon->d = c->line;
                ucon->mode = connected_pair;
                CSTATE_MUT(c) = ucon;
                self->dw->downStream(self->dw, newEstContext(c->line));
                initiateConnect(self);
            }
            else
            {
                atomic_fetch_add_explicit(&(state->active_cons), 1, memory_order_relaxed);
                preconnect_client_con_state_t *dcon = create_cstate(c->line->tid);
                CSTATE_MUT(c) = dcon;
                dcon->mode = connected_direct;
                self->up->upStream(self->up, c);
                return;
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            preconnect_client_con_state_t *dcon = CSTATE(c);
            CSTATE_MUT(c) = NULL;
            atomic_fetch_add_explicit(&(state->active_cons), -1, memory_order_relaxed);

            switch (dcon->mode)
            {
            case connected_direct:
                destroy_cstate(dcon);
                self->up->upStream(self->up, c);
                break;

            case connected_pair:;
                line_t *u_line = dcon->u;
                (dcon->u->chains_state)[self->chain_index] = NULL;
                context_t * fctx =  switchLine(c, u_line); // created here to prevent destruction of line
                destroy_cstate(dcon);
                self->up->upStream(self->up,fctx);
                break;
            case notconnected:
            default:
                LOGF("PreConnectClient: invalid value of connection state (memory error?)");
                exit(1);

                break;
            }
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    preconnect_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {

        preconnect_client_con_state_t *cstate = CSTATE(c);

        switch (cstate->mode)
        {
        case connected_direct:
            self->dw->downStream(self->dw, c);
            break;

        case connected_pair:
            self->dw->downStream(self->dw, switchLine(c, cstate->d));
            break;

        case notconnected:
            LOGE("PreConnectClient: this node is not purposed to handle downstream data before pairing");
        default:
            LOGF("PreConnectClient: invalid value of connection state (memory error?)");
            exit(1);

            break;
        }
    }
    else
    {
        const unsigned int tid = c->line->tid;
        thread_box_t *this_tb = &(state->threads[tid]);
        preconnect_client_con_state_t *ucon = CSTATE(c);

        if (c->fin)
        {
            CSTATE_MUT(c) = NULL;

            switch (ucon->mode)
            {
            case connected_direct:
                atomic_fetch_add_explicit(&(state->active_cons), -1, memory_order_relaxed);
                destroy_cstate(ucon);
                self->dw->downStream(self->dw, c);
                break;

            case connected_pair:;
                atomic_fetch_add_explicit(&(state->active_cons), -1, memory_order_relaxed);
                line_t *d_line = ucon->d;
                (ucon->d->chains_state)[self->chain_index] = NULL;
                destroy_cstate(ucon);
                self->dw->downStream(self->dw, switchLine(c, d_line));
                break;

            case notconnected:
                if (ucon->prev != NULL)
                {
                    // fin after est
                    atomic_fetch_add_explicit(&(state->unused_cons), -1, memory_order_relaxed);
                    remove_connection(this_tb, ucon);
                }
                destroy_cstate(ucon);
                destroyContext(c);
                break;

            default:
                LOGF("PreConnectClient: invalid value of connection state (memory error?)");
                exit(1);

                break;
            }
            LOGD("PreConnectClient: disconnected, unused: %d active: %d", state->unused_cons, STATE(self)->active_cons);
            initiateConnect(self);
        }
        else if (c->est)
        {
            if (ucon->mode == notconnected)
            {
                add_connection(this_tb, ucon);
                destroyContext(c);
                unsigned int unused = atomic_fetch_add_explicit(&(state->unused_cons), 1, memory_order_relaxed);
                LOGI("PreConnectClient: connected,    unused: %d active: %d", unused + 1, state->active_cons);
                initiateConnect(self);
            }
            else
                self->dw->downStream(self->dw, c);
        }
    }
}
static void preConnectClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void preConnectClientPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void preConnectClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void preConnectClientPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void start_preconnect(htimer_t *timer)
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
tunnel_t *newPreConnectClient(node_instance_context_t *instance_info)
{
    const size_t start_delay_ms = 150;

    preconnect_client_state_t *state = malloc(sizeof(preconnect_client_state_t) + (threads_count * sizeof(thread_box_t)));
    memset(state, 0, sizeof(preconnect_client_state_t) + (threads_count * sizeof(thread_box_t)));
    const cJSON *settings = instance_info->node_settings_json;

    getIntFromJsonObject(&(state->min_unused_cons), settings, "minimum-unused");

    state->min_unused_cons = min(max(threads_count * 2, state->min_unused_cons), 128);
    state->connection_per_thread = state->min_unused_cons / threads_count;

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &preConnectClientUpStream;
    t->packetUpStream = &preConnectClientPacketUpStream;
    t->downStream = &preConnectClientDownStream;
    t->packetDownStream = &preConnectClientPacketDownStream;

    htimer_t *start_timer = htimer_add(loops[0], start_preconnect, start_delay_ms, 1);
    hevent_set_userdata(start_timer, t);

    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiPreConnectClient(tunnel_t *self, char *msg)
{
    LOGE("preConnectClient API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyPreConnectClient(tunnel_t *self)
{
    LOGE("preConnectClient DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataPreConnectClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}