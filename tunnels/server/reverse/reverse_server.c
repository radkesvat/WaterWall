#include "reverse_server.h"
#include "buffer_pool.h"
#include "helpers.h"
#include "hplatform.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "types.h"
#include "ww.h"

static void flushWriteQueue(tunnel_t *self, reverse_server_con_state_t *cstate)
{
    if (contextQueueLen(cstate->uqueue) > 0)
    {
        line_t *down_line = cstate->d;
        while (isAlive(down_line) && contextQueueLen(cstate->uqueue) > 0)
        {
            self->dw->downStream(self->dw, switchLine(contextQueuePop(cstate->uqueue), down_line));
        }
    }
}

static void upStream(tunnel_t *self, context_t *c)
{

    reverse_server_state_t     *state   = STATE(self);
    reverse_server_con_state_t *dcstate = CSTATE_D(c);

    if (c->payload != NULL)
    {
        if (dcstate->paired)
        {
            self->up->upStream(self->up, switchLine(c, CSTATE_D(c)->u));
        }
        else
        {
            if (dcstate->handshaked)
            {
                bufferStreamPush(dcstate->wait_stream, c->payload);
                c->payload = NULL;
                destroyContext(c);
            }
            else
            {
                bufferStreamPush(dcstate->wait_stream, c->payload);
                c->payload = NULL;

                if (bufferStreamLen(dcstate->wait_stream) >= 96)
                {
                    shift_buffer_t *data = bufferStreamRead(dcstate->wait_stream,96);

                    dcstate->handshaked = true;
                    for (int i = 0; i < 96; i++)
                    {
                        if (((uint8_t *) rawBuf(data))[i] != 0xFF)
                        {
                            dcstate->handshaked = false;
                            break;
                        }
                    }
                    reuseBuffer(getContextBufferPool(c), data);

                    thread_box_t *this_tb = &(state->threadlocal_pool[c->line->tid]);

                    if (dcstate->handshaked)
                    {
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

                            flushWriteQueue(self, ucstate);
                            if (! isAlive(c->line))
                            {
                                destroyContext(c);
                                return;
                            }
                            if (bufferStreamLen(dcstate->wait_stream) > 0)
                            {
                                c->payload = bufferStreamFullRead(dcstate->wait_stream);
                                self->up->upStream(self->up, switchLine(c, ucstate->u));
                            }
                            else
                            {
                                destroyContext(c);
                            }
                        }
                        else
                        {
                            addConnectionD(this_tb, dcstate);
                            destroyContext(c);
                        }
                    }
                    else
                    {
                        CSTATE_D_MUT(c)                                  = NULL;
                        cleanup(dcstate);
                        self->dw->downStream(self->dw, newFinContextFrom(c));
                        destroyContext(c);
                        return;
                    }
                }
                else
                {
                    destroyContext(c);
                    return;
                }
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
            self->dw->downStream(self->dw, newEstContext(c->line));

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
            c->first              = false;
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
                if (! isAlive(c->line))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                if (bufferStreamLen(dcstate->wait_stream) > 0)
                {
                    bufferStreamPush(dcstate->wait_stream, c->payload);
                    c->payload                  = NULL;
                    context_t *data_waiting_ctx = newContext(c->line);
                    data_waiting_ctx->payload   = bufferStreamFullRead(dcstate->wait_stream);
                    self->up->upStream(self->up, data_waiting_ctx);
                }
                else
                {

                    self->dw->downStream(self->dw, switchLine(c, dcstate->d));
                }
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
            self->up->upStream(self->up, newEstContext(c->line));

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
