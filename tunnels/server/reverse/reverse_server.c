#include "reverse_server.h"
#include "buffer_pool.h"
#include "helpers.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "types.h"
#include "ww.h"

enum
{
    kHandShakeByte   = 0xFF,
    kHandShakeLength = 96
};

#define VAL_1X  kHandShakeByte
#define VAL_2X  VAL_1X, VAL_1X
#define VAL_4X  VAL_2X, VAL_2X
#define VAL_8X  VAL_4X, VAL_4X
#define VAL_16X VAL_8X, VAL_8X
#define VAL_32X VAL_16X, VAL_16X
#define VAL_64X VAL_32X, VAL_32X

static void flushWriteQueue(tunnel_t *self, reverse_server_con_state_t *cstate)
{
    if (contextQueueLen(cstate->uqueue) > 0)
    {
        line_t *down_line = cstate->d;
        while (isAlive(down_line) && contextQueueLen(cstate->uqueue) > 0)
        {
            if (isDownPiped(down_line))
            {
                pipeDownStream(switchLine(contextQueuePop(cstate->uqueue), down_line));
            }
            else
            {
                self->dw->downStream(self->dw, switchLine(contextQueuePop(cstate->uqueue), down_line));
            }
        }
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    if (isUpPiped(c->line))
    {
        pipeUpStream(c);
        return;
    }

    reverse_server_state_t     *state   = TSTATE(self);
    reverse_server_con_state_t *dcstate = c->line->up_state;

    if (c->payload != NULL)
    {
        if (dcstate->paired)
        {
            self->up->upStream(self->up, switchLine(c, dcstate->u));
        }
        else
        {
            bufferStreamPushContextPayload(dcstate->wait_stream, c);

            if (dcstate->handshaked)
            {
                destroyContext(c);
            }
            else
            {
                if (bufferStreamLen(dcstate->wait_stream) >= kHandShakeLength)
                {
                    shift_buffer_t *data = bufferStreamRead(dcstate->wait_stream, kHandShakeLength);

                    static const uint8_t kHandshakeExpecetd[kHandShakeLength] = {VAL_64X, VAL_32X};

                    dcstate->handshaked = 0 == memcmp(kHandshakeExpecetd, rawBuf(data), kHandShakeLength);

                    thread_box_t *this_tb = &(state->threadlocal_pool[c->line->tid]);

                    if (dcstate->handshaked)
                    {
                        // atomic access here is not for thread safety since it is our own thread,
                        // but regular access would be SEQ_CST
                        if (atomic_load_explicit(&(this_tb->u_count), memory_order_relaxed) > 0)
                        {
                            reuseBuffer(getContextBufferPool(c), data);

                            reverse_server_con_state_t *ucstate = this_tb->u_cons_root.next;

                            // size_t random_choosen = (fastRand() % this_tb->u_count);
                            // while (random_choosen--)
                            // {
                            //     ucstate = ucstate->next;
                            // }

                            removeConnectionU(this_tb, ucstate);
                            ucstate->d           = c->line;
                            ucstate->paired      = true;
                            ucstate->wait_stream = dcstate->wait_stream;
                            dcstate->wait_stream = NULL;
                            doneLineUpSide(c->line);
                            setupLineUpSide(c->line, onLinePausedD, ucstate, onLineResumedD);

                            wwmGlobalFree(dcstate);
                            flushWriteQueue(self, ucstate);

                            if (! isAlive(c->line))
                            {
                                destroyContext(c);
                                return;
                            }
                            if (bufferStreamLen(ucstate->wait_stream) > 0)
                            {
                                c->payload = bufferStreamFullRead(ucstate->wait_stream);
                                self->up->upStream(self->up, switchLine(c, ucstate->u));
                            }
                            else
                            {
                                destroyContext(c);
                            }
                        }
                        else
                        {
                            for (unsigned int i = 0; i < workers_count; i++)
                            {
                                if (atomic_load_explicit(&(state->threadlocal_pool[i].u_count), memory_order_relaxed) >
                                    0)
                                {

                                    c->payload = data;
                                    if (bufferStreamLen(dcstate->wait_stream) > 0)
                                    {
                                        c->payload = appendBufferMerge(getContextBufferPool(c), c->payload,
                                                                       bufferStreamFullRead(dcstate->wait_stream));
                                    }
                                    cleanup(dcstate);
                                    pipeTo(self, c->line, i);
                                    pipeUpStream(c);
                                    return; // piped to another worker which has waiting connections
                                }
                            }
                            reuseBuffer(getContextBufferPool(c), data);

                            addConnectionD(this_tb, dcstate);
                            destroyContext(c);
                        }
                    }
                    else
                    {
                        cleanup(dcstate);
                        if (isDownPiped(c->line))
                        {
                            pipeDownStream(newFinContextFrom(c));
                        }
                        else
                        {
                            self->dw->downStream(self->dw, newFinContextFrom(c));
                        }
                        destroyContext(c);
                        return;
                    }
                }
                else
                {
                    destroyContext(c);
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
            dcstate = createCstateD(c->line);
            if (isDownPiped(c->line))
            {
                // pipe dose not care
            }
            else
            {
                self->dw->downStream(self->dw, newEstContext(c->line));
            }
            destroyContext(c);
        }
        else if (c->fin)
        {

            if (dcstate->paired)
            {
                line_t *u_line = dcstate->u;
                cleanup(dcstate);
                self->up->upStream(self->up, switchLine(c, u_line));
            }
            else
            {
                // unpaired connections have no line setup
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

    reverse_server_state_t     *state   = TSTATE(self);
    reverse_server_con_state_t *ucstate = c->line->up_state;

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
                // CSTATE_U_MUT(c)                                = dcstate;
                // LSTATE_I_MUT(dcstate->d, state->chain_index_d) = dcstate;
                if (! isAlive(c->line))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                if (bufferStreamLen(dcstate->wait_stream) > 0)
                {
                    bufferStreamPushContextPayload(dcstate->wait_stream, c);

                    context_t *data_waiting_ctx = newContext(c->line);
                    data_waiting_ctx->payload   = bufferStreamFullRead(dcstate->wait_stream);
                    self->up->upStream(self->up, data_waiting_ctx);
                }
                else
                {
                    if (isDownPiped(dcstate->d))
                    {
                        pipeDownStream(switchLine(c, dcstate->d));
                    }
                    else
                    {
                        self->dw->downStream(self->dw, switchLine(c, dcstate->d));
                    }
                }
            }
            else
            {
                LOGW("reverseServer: no peer left, waiting tid: %d", c->line->tid);
                ucstate = createCstateU(c->line);
                addConnectionU(this_tb, ucstate);
                contextQueuePush(ucstate->uqueue, c);
            }
        }
        else
        {
            if (ucstate->paired)
            {
                if (isDownPiped(ucstate->d))
                {
                    pipeDownStream(switchLine(c, ucstate->d));
                }
                else
                {
                    self->dw->downStream(self->dw, switchLine(c, ucstate->d));
                }
            }
            else
            {
                contextQueuePush(ucstate->uqueue, c);
            }
        }
    }
    else
    {
        if (c->init)
        {

            self->up->upStream(self->up, newEstContext(c->line));

            destroyContext(c);
        }
        else if (c->fin)
        {
            if (ucstate == NULL)
            {
                destroyContext(c);
                return;
            }

            if (ucstate->paired)
            {
                line_t *downline = ucstate->d;
                cleanup(ucstate);
                c = switchLine(c, downline);

                if (isDownPiped(c->line))
                {
                    pipeDownStream(c);
                }
                else
                {
                    self->dw->downStream(self->dw, c);
                }
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
    reverse_server_state_t *state = wwmGlobalMalloc(sizeof(reverse_server_state_t) + (workers_count * sizeof(thread_box_t)));
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
