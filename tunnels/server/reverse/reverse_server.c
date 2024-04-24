#include "reverse_server.h"
#include "helpers.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "types.h"

static void flushWriteQueue(tunnel_t *self, reverse_server_con_state_t *cstate)
{

    if (contextQueueLen(cstate->uqueue) > 0)
    {
        reverse_server_state_t *state     = STATE(self);
        line_t *                down_line = cstate->d;
        while (contextQueueLen(cstate->uqueue) > 0)
        {

            if (! cstate->signal_sent)
            {
                cstate->signal_sent = true;
                context_t *c        = switchLine(contextQueuePop(cstate->uqueue), cstate->d);
                shiftl(c->payload, 1);
                writeUI8(c->payload, 0xFF);
                self->dw->downStream(self->dw, c);
            }
            else
            {
                self->dw->downStream(self->dw, switchLine(contextQueuePop(cstate->uqueue), cstate->d));
            }
            if (! isAlive(down_line))
            {
                return;
            }
        }
    }
    else
    {
        cstate->signal_sent = true;
        shift_buffer_t *buf = popBuffer(getLineBufferPool(cstate->d));
        shiftl(buf, 1);
        writeUI8(buf, 0xFF);
        context_t *c = newContext(cstate->d);
        c->payload   = buf;
        self->dw->downStream(self->dw, c);
    }
}

static inline void upStream(tunnel_t *self, context_t *c)
{

    reverse_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        if (CSTATE_D(c)->paired)
        {
            self->up->upStream(self->up, switchLine(c, CSTATE_D(c)->u));
        }
        else
        {
            // a real pair will not send that before it receives something
            reuseBuffer(getContextBufferPool(c), c->payload);
            c->payload = NULL;
            destroyContext(c);
        }
    }
    else
    {
        const uint8_t tid     = c->line->tid;
        thread_box_t *     this_tb = &(state->threadlocal_pool[tid]);
        if (c->init)
        {
            if (state->chain_index_d == 0)
            {
                state->chain_index_d = reserveChainStateIndex(c->line);
            }

            if (this_tb->u_count > 0)
            {
                reverse_server_con_state_t *ucstate = this_tb->u_cons_root.next;
                removeConnectionU(this_tb, ucstate);
                ucstate->d      = c->line;
                ucstate->paired = true;
                CSTATE_D_MUT(c) = ucstate;
                self->up->upStream(self->up, newEstContext(ucstate->u));
                self->dw->downStream(self->dw, newEstContext(c->line));
                flushWriteQueue(self, ucstate);
            }
            else
            {
                reverse_server_con_state_t *dcstate = createCstate(false, c->line);
                CSTATE_D_MUT(c)                     = dcstate;
                addConnectionD(this_tb, dcstate);
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *dcstate = CSTATE_D(c);
            CSTATE_D_MUT(c)                     = NULL;

            if (dcstate->paired)
            {
                line_t *u_line                                   = dcstate->u;
                (dcstate->u->chains_state)[state->chain_index_u] = NULL;
                destroyCstate(dcstate);
                self->up->upStream(self->up, switchLine(c, u_line));
            }
            else
            {
                removeConnectionD(this_tb, dcstate);
                destroyCstate(dcstate);
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
        {
            self->dw->downStream(self->dw, switchLine(c, CSTATE_U(c)->d));
        }
        else
        {
            contextQueuePush(CSTATE_U(c)->uqueue, c);
        }
    }
    else
    {
        const uint8_t tid     = c->line->tid;
        thread_box_t *     this_tb = &(state->threadlocal_pool[tid]);
        if (c->init)
        {
            if (state->chain_index_u == 0)
            {
                state->chain_index_u = reserveChainStateIndex(c->line);
            }

            if (this_tb->d_count > 0)
            {

                reverse_server_con_state_t *dcstate = this_tb->d_cons_root.next;
                removeConnectionD(this_tb, dcstate);
                dcstate->u                                       = c->line;
                dcstate->paired                                  = true;
                CSTATE_U_MUT(c)                                  = dcstate;
                (dcstate->d->chains_state)[state->chain_index_d] = dcstate;
                self->up->upStream(self->up, newEstContext(c->line));
                if (CSTATE_U(c) == NULL)
                {
                    destroyContext(c);
                    return;
                }
                self->dw->downStream(self->dw, newEstContext(dcstate->d));
                if (CSTATE_U(c) == NULL)
                {
                    destroyContext(c);
                    return;
                }

                dcstate->signal_sent = true;
                shift_buffer_t *buf  = popBuffer(getLineBufferPool(dcstate->d));
                shiftl(buf, 1);
                writeUI8(buf, 0xFF);
                context_t *c = newContext(dcstate->d);
                c->payload   = buf;
                self->dw->downStream(self->dw, c);
            }
            else
            {
                LOGW("reverseServer: no peer left, waiting tid: %d", c->line->tid);
                reverse_server_con_state_t *ucstate = createCstate(true, c->line);
                CSTATE_U_MUT(c)                     = ucstate;
                addConnectionU(this_tb, ucstate);
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *ucstate = CSTATE_U(c);
            CSTATE_U_MUT(c)                     = NULL;

            if (ucstate->paired)
            {
                line_t *d_line                                   = ucstate->d;
                (ucstate->d->chains_state)[state->chain_index_d] = NULL;

                destroyCstate(ucstate);
                self->dw->downStream(self->dw, switchLine(c, d_line));
            }
            else
            {
                removeConnectionU(this_tb, ucstate);
                destroyCstate(ucstate);
                destroyContext(c);
            }
        }
    }
}

tunnel_t *newReverseServer(node_instance_context_t *instance_info)
{
    (void) instance_info;
    reverse_server_state_t *state = malloc(sizeof(reverse_server_state_t) + (workers_count * sizeof(thread_box_t)));
    memset(state, 0, sizeof(reverse_server_state_t) + (workers_count * sizeof(thread_box_t)));

    tunnel_t *t         = newTunnel();
    t->state            = state;
    t->upStream         = &upStream;
    t->downStream       = &downStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiReverseServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0}; // TODO(root):
}

tunnel_t *destroyReverseServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataReverseServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}