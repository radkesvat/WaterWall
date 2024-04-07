#include "reverse_server.h"
#include "managers/node_manager.h"
#include "loggers/network_logger.h"
#include "types.h"
#include "helpers.h"

static void flush_write_queue(tunnel_t *self, reverse_server_con_state_t *cstate)
{

    while (contextQueueLen(cstate->uqueue) > 0)
    {
        self->dw->downStream(self->dw, switchLine(contextQueuePop(cstate->uqueue), cstate->d));

        // 1 context is stalled form the caller, so this will not be read after free
        if (cstate->d->chains_state[STATE(self)->chain_index_d] == NULL)
            return;
    }
}

static inline void upStream(tunnel_t *self, context_t *c)
{

    reverse_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        if (CSTATE_D(c)->paired)
            self->up->upStream(self->up, switchLine(c, CSTATE_D(c)->u));
        else
        {
            // a real pair will not send that before it receives something
            DISCARD_CONTEXT(c);
            destroyContext(c);
        }
    }
    else
    {
        const unsigned int tid = c->line->tid;
        thread_box_t *this_tb = &(state->threads[tid]);
        if (c->init)
        {
            if (state->chain_index_d == 0)
                state->chain_index_d = reserveChainStateIndex(c->line);

            if (this_tb->u_count > 0)
            {
                reverse_server_con_state_t *ucstate = qcons_pull(&this_tb->u_cons);
                ucstate->d = c->line;
                ucstate->paired = true;
                ucstate->samethread = true;
                CSTATE_D_MUT(c) = ucstate;
                this_tb->u_count -= 1;
                self->up->upStream(self->up, newEstContext(ucstate->u));
                self->dw->downStream(self->dw, newEstContext(c->line));
                flush_write_queue(self, ucstate);

            }
            else
            {
                reverse_server_con_state_t *dcstate = create_cstate(false, c->line);
                CSTATE_D_MUT(c) = dcstate;
                qcons_push(&(this_tb->d_cons), dcstate);
                this_tb->d_count += 1;
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *dcstate = CSTATE_D(c);
            CSTATE_D_MUT(c) = NULL;

            if (dcstate->paired)
            {
                line_t *u_line = dcstate->u;
                (dcstate->u->chains_state)[state->chain_index_u] = NULL;
                destroy_cstate(dcstate);
                self->up->upStream(self->up, switchLine(c, u_line));
            }
            else
            {
                size_t len = qcons_size(&(this_tb->d_cons));
                while (len--)
                {
                    reverse_server_con_state_t *q_dcs = qcons_pull(&(this_tb->d_cons));
                    if (q_dcs == dcstate)
                    {
                        this_tb->d_count -= 1;
                        destroy_cstate(dcstate);
                        break;
                    }
                    else
                        qcons_push(&(this_tb->d_cons), q_dcs);
                }
                destroyContext(c);

            }
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    reverse_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        if (CSTATE_U(c)->paired)
            self->dw->downStream(self->dw, switchLine(c, CSTATE_U(c)->d));
        else
        {
            contextQueuePush(CSTATE_U(c)->uqueue, c);
        }
    }
    else
    {
        const unsigned int tid = c->line->tid;
        thread_box_t *this_tb = &(state->threads[tid]);
        if (c->init)
        {
            if (state->chain_index_u == 0)
                state->chain_index_u = reserveChainStateIndex(c->line);

            if (this_tb->d_count > 0)
            {
                reverse_server_con_state_t *dcstate = qcons_pull(&this_tb->d_cons);
                dcstate->u = c->line;
                dcstate->paired = true;
                dcstate->samethread = true;
                CSTATE_U_MUT(c) = dcstate;
                (dcstate->d->chains_state)[state->chain_index_d] = dcstate;
                this_tb->d_count -= 1;
                self->up->upStream(self->up, newEstContext(c->line));
                self->dw->downStream(self->dw, newEstContext(dcstate->d));
            }
            else
            {
                LOGW("reverseServer: no peer left, waiting tid: %d",c->line->tid);
                reverse_server_con_state_t *ucstate = create_cstate(true, c->line);
                CSTATE_U_MUT(c) = ucstate;
                qcons_push(&(this_tb->u_cons), ucstate);
                this_tb->u_count += 1;
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *ucstate = CSTATE_U(c);
            CSTATE_U_MUT(c) = NULL;

            if (ucstate->paired)
            {
                line_t *d_line = ucstate->d;
                (ucstate->d->chains_state)[state->chain_index_d] = NULL;

                destroy_cstate(ucstate);
                self->dw->downStream(self->dw, switchLine(c, d_line));
            }
            else
            {
                size_t len = qcons_size(&(this_tb->u_cons));
                while (len--)
                {
                    reverse_server_con_state_t *q_ucs = qcons_pull(&(this_tb->u_cons));
                    if (q_ucs == ucstate)
                    {
                        this_tb->u_count -= 1;
                        destroy_cstate(ucstate);
                        break;
                    }
                    else
                        qcons_push(&(this_tb->u_cons), q_ucs);
                }
                destroyContext(c);

            }
        }
    }
}
static void reverseServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void reverseServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void reverseServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void reverseServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newReverseServer(node_instance_context_t *instance_info)
{

    reverse_server_state_t *state = malloc(sizeof(reverse_server_state_t) + (threads_count * sizeof(thread_box_t)));
    memset(state, 0, sizeof(reverse_server_state_t) + (threads_count * sizeof(thread_box_t)));

    for (size_t i = 0; i < threads_count; i++)
    {
        state->threads[i].d_cons = qcons_with_capacity(64);
        state->threads[i].u_cons = qcons_with_capacity(64);
    }

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &reverseServerUpStream;
    t->packetUpStream = &reverseServerPacketUpStream;
    t->downStream = &reverseServerDownStream;
    t->packetDownStream = &reverseServerPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiReverseServer(tunnel_t *self, char *msg)
{
    LOGE("reverseServer API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyReverseServer(tunnel_t *self)
{
    LOGE("reverseServer DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataReverseServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = TFLAG_ROUTE_STARTER};
}