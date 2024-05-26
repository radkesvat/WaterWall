#include "reverse_server.h"
#include "buffer_pool.h"
#include "helpers.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "types.h"
#include "ww.h"

static void flushWriteQueue(tunnel_t *self, reverse_server_con_state_t *cstate)
{

    if (contextQueueLen(cstate->uqueue) > 0)
    {
        line_t *down_line = cstate->d;
        while (contextQueueLen(cstate->uqueue) > 0)
        {

            self->dw->downStream(self->dw, switchLine(contextQueuePop(cstate->uqueue), down_line));

            if (! isAlive(down_line))
            {

                return;
            }
        }
    }
}

static void upStream(tunnel_t *self, context_t *c)
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
            thread_box_t               *this_tb = &(state->threadlocal_pool[c->line->tid]);
            reverse_server_con_state_t *dcstate = CSTATE_D(c);

            // first byte is 0xFF a signal from reverse client
            uint8_t check = 0x0;
            readUI8(c->payload, &check);
            shiftr(c->payload, 1);
            if (dcstate->handshaked || check != (unsigned char) 0xFF)
            {
                CSTATE_D_MUT(c)                                  = NULL;
                (dcstate->u->chains_state)[state->chain_index_u] = NULL;
                cleanup(dcstate);
                self->dw->downStream(self->dw, newFinContextFrom(c));
                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }
            dcstate->handshaked = true;

            context_t *hello_data_ctx = newContextFrom(c);
            hello_data_ctx->payload   = popBuffer(getContextBufferPool(c));
            setLen(hello_data_ctx->payload, 1);
            writeUI8(hello_data_ctx->payload, 0xFF);
            self->dw->downStream(self->dw, hello_data_ctx);

            if (! isAlive(c->line))
            {
                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }

            if (this_tb->u_count > 0)
            {
                reverse_server_con_state_t *ucstate = this_tb->u_cons_root.next;
                removeConnectionU(this_tb, ucstate);
                ucstate->d      = c->line;
                ucstate->paired = true;
                setupLineUpSide(ucstate->u, onLinePausedU, ucstate, onLineResumedU);
                setupLineUpSide(ucstate->d, onLinePausedD, ucstate, onLineResumedD);

                cleanup(CSTATE_D(c));
                CSTATE_D_MUT(c)                                  = ucstate;
                (ucstate->u->chains_state)[state->chain_index_u] = ucstate;
                self->dw->downStream(self->dw, newEstContext(c->line));
                if (! isAlive(c->line))
                {

                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                self->up->upStream(self->up, newEstContext(ucstate->u));
                if (! isAlive(c->line))
                {

                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                flushWriteQueue(self, ucstate);

                if (bufLen(c->payload) > 0)
                {
                    if (! isAlive(c->line))
                    {
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                    self->up->upStream(self->up, switchLine(c, ucstate->u));
                }
                else
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                }
            }
            else
            {
                if (bufLen(c->payload) > 0)
                {
                    dcstate->waiting_d = c->payload;
                    c->payload         = NULL;
                }
                else
                {
                    reuseContextBuffer(c);
                }
                addConnectionD(this_tb, dcstate);
                destroyContext(c);
            }
            return;
        }
    }
    else
    {
        const uint8_t tid     = c->line->tid;
        thread_box_t *this_tb = &(state->threadlocal_pool[tid]);
        if (c->init)
        {
            if (WW_UNLIKELY(state->chain_index_d == 0))
            {
                state->chain_index_d = reserveChainStateIndex(c->line);
            }
            reverse_server_con_state_t *dcstate = createCstate(false, c->line);
            CSTATE_D_MUT(c)                     = dcstate;

            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *dcstate = CSTATE_D(c);
            CSTATE_D_MUT(c)                     = NULL;

            if (dcstate->paired)
            {
                doneLineUpSide(dcstate->d);
                doneLineUpSide(dcstate->u);
                line_t *u_line                                   = dcstate->u;
                (dcstate->u->chains_state)[state->chain_index_u] = NULL;
                cleanup(dcstate);
                self->up->upStream(self->up, switchLine(c, u_line));
            }
            else
            {
                if (dcstate->handshaked)
                {
                    if (dcstate->waiting_d)
                    {
                        reuseBuffer(getContextBufferPool(c), dcstate->waiting_d);
                        dcstate->waiting_d = NULL;
                    }
                    removeConnectionD(this_tb, dcstate);
                }
                cleanup(dcstate);
                destroyContext(c);
            }
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    reverse_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        if (c->first)
        {
            const uint8_t tid     = c->line->tid;
            thread_box_t *this_tb = &(state->threadlocal_pool[tid]);

            if (this_tb->d_count > 0)
            {
                reverse_server_con_state_t *dcstate = this_tb->d_cons_root.next;
                removeConnectionD(this_tb, dcstate);
                dcstate->u      = c->line;
                dcstate->paired = true;
                setupLineUpSide(dcstate->u, onLinePausedU, dcstate, onLineResumedU);
                setupLineUpSide(dcstate->d, onLinePausedD, dcstate, onLineResumedD);
                CSTATE_U_MUT(c)                                  = dcstate;
                (dcstate->d->chains_state)[state->chain_index_d] = dcstate;
                self->up->upStream(self->up, newEstContext(c->line));
                if (! isAlive(c->line))
                {

                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                self->dw->downStream(self->dw, newEstContext(dcstate->d));
                if (! isAlive(c->line))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                if (dcstate->waiting_d)
                {
                    context_t *data_waiting_ctx = newContext(c->line);
                    data_waiting_ctx->payload   = dcstate->waiting_d;
                    dcstate->waiting_d          = NULL;
                    self->up->upStream(self->up, data_waiting_ctx);

                    if (! isAlive(c->line))
                    {
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                }
                self->dw->downStream(self->dw, switchLine(c, dcstate->d));
            }
            else
            {
                LOGW("reverseServer: no peer left, waiting tid: %d", c->line->tid);
                reverse_server_con_state_t *ucstate = createCstate(true, c->line);
                CSTATE_U_MUT(c)                     = ucstate;
                addConnectionU(this_tb, ucstate);
                contextQueuePush(ucstate->uqueue, c);
            }
        }
        else
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
    }
    else
    {
        if (c->init)
        {
            if (WW_UNLIKELY(state->chain_index_u == 0))
            {
                state->chain_index_u = reserveChainStateIndex(c->line);
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            reverse_server_con_state_t *ucstate = CSTATE_U(c);
            if (ucstate == NULL)
            {
                destroyContext(c);
                return;
            }

            CSTATE_U_MUT(c) = NULL;

            if (ucstate->paired)
            {
                doneLineUpSide(ucstate->d);
                doneLineUpSide(ucstate->u);
                line_t *d_line                                   = ucstate->d;
                (ucstate->d->chains_state)[state->chain_index_d] = NULL;

                cleanup(ucstate);
                self->dw->downStream(self->dw, switchLine(c, d_line));
            }
            else
            {
                const uint8_t tid     = c->line->tid;
                thread_box_t *this_tb = &(state->threadlocal_pool[tid]);
                removeConnectionU(this_tb, ucstate);
                cleanup(ucstate);
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

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiReverseServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyReverseServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataReverseServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}
