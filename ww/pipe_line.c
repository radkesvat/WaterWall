#include "pipe_line.h"
#include "buffer_pool.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct msg_event
{
    pipe_line_t *pl;
    void        *function;
    void        *arg;
};

typedef void (*MsgTargetFunction)(pipe_line_t *pl, void *arg);

static void lock(pipe_line_t *pl)
{
    int old_refc = atomic_fetch_add_explicit(&pl->refc, 1, memory_order_relaxed);
    if (old_refc == 0)
    {
        // this should not happen, otherwise we must use acquire/release
        LOGF("PipeLine: thread-safety done incorrectly lock()");
        exit(1);
    }
}
static void unlock(pipe_line_t *pl)
{
    int old_refc = atomic_fetch_add_explicit(&pl->refc, -1, memory_order_relaxed);
    if (old_refc == 1)
    {
        if (! atomic_load_explicit(&(pl->closed), memory_order_relaxed))
        {
            // this should not happen, otherwise we must use acquire/release
            LOGF("PipeLine: thread-safety done incorrectly unlock()");
            exit(1);
        }
        free(pl);
    }
}
static void onMsgReceived(hevent_t *ev)
{
    struct msg_event *msg_ev = hevent_userdata(ev);
    (*(MsgTargetFunction *) (&(msg_ev->function)))(msg_ev->pl, msg_ev->arg);
    unlock(msg_ev->pl);
    free(msg_ev);
}

static void sendMessage(pipe_line_t *pl, MsgTargetFunction fn, void *arg, uint8_t tid_from, uint8_t tid_to)
{
    if (tid_from == tid_to)
    {
        fn(pl, arg);
        return;
    }
    lock(pl);
    struct msg_event *evdata = malloc(sizeof(struct msg_event));
    *evdata                  = (struct msg_event){.pl = pl, .function = *(void **) (&fn), .arg = arg};

    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = loops[tid_to];
    ev.cb   = onMsgReceived;
    hevent_set_userdata(&ev, evdata);
    hloop_post_event(loops[tid_to], &ev);
}

void writeBufferToLeftSide(pipe_line_t *pl, void *arg)
{
    shift_buffer_t *buf = arg;
    if (pl->right_line == NULL)
    {
        reuseBuffer(buffer_pools[pl->left_tid], buf);
        return;
    }
    context_t *ctx = newContext(pl->left_line);
    ctx->payload   = buf;
    pl->local_down_stream(pl->self, ctx);
}

void writeBufferToRightSide(pipe_line_t *pl, void *arg)
{
    shift_buffer_t *buf = arg;
    if (pl->right_line == NULL)
    {
        reuseBuffer(buffer_pools[pl->right_tid], buf);
        return;
    }
    context_t *ctx = newContext(pl->right_line);
    ctx->payload   = buf;
    pl->local_up_stream(pl->self, ctx);
}

void finishLeftSide(pipe_line_t *pl, void *arg)
{
    (void) arg;

    if (pl->left_line == NULL)
    {
        return;
    }
    context_t *fctx = newFinContext(pl->left_line);
    doneLineUpSide(pl->left_line);
    destroyLine(pl->left_line);
    pl->left_line = NULL;
    pl->local_down_stream(pl->self, fctx);
}

void finishRightSide(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->right_line == NULL)
    {
        return;
    }
    context_t *fctx = newFinContext(pl->right_line);
    doneLineDownSide(pl->right_line);
    destroyLine(pl->right_line);
    pl->right_line = NULL;
    pl->local_up_stream(pl->self, fctx);
}

void pauseLeftLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->left_line == NULL)
    {
        return;
    }
    pauseLineDownSide(pl->left_line);
}

void pauseRightLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->right_line == NULL)
    {
        return;
    }
    pauseLineUpSide(pl->right_line);
}

void resumeLeftLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->left_line == NULL)
    {
        return;
    }
    resumeLineDownSide(pl->left_line);
}

void resumeRightLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->right_line == NULL)
    {
        return;
    }
    resumeLineUpSide(pl->right_line);
}

void onLeftLinePaused(void *state)
{
    pipe_line_t *pl = state;
    sendMessage(pl, pauseRightLine, NULL, pl->left_tid, pl->right_tid);
}

void onRightLinePaused(void *state)
{
    pipe_line_t *pl = state;
    sendMessage(pl, pauseLeftLine, NULL, pl->right_tid, pl->left_tid);
}

void onLeftLineResumed(void *state)
{
    pipe_line_t *pl = state;
    sendMessage(pl, resumeRightLine, NULL, pl->left_tid, pl->right_tid);
}

void onRightLineResumed(void *state)
{
    pipe_line_t *pl = state;
    sendMessage(pl, pauseLeftLine, NULL, pl->right_tid, pl->left_tid);
}

bool writePipeLineLTR(pipe_line_t *pl, context_t *c)
{
    // other flags are not supposed to come to pipe line
    assert(c->fin || c->payload != NULL);

    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return false;
    }

    if (c->fin)
    {
        assert(pl->left_line);
        doneLineUpSide(pl->left_line);
        destroyLine(pl->left_line);
        pl->left_line = NULL;

        bool expected = false;

        if (atomic_compare_exchange_strong_explicit(&(pl->closed), &expected, true, memory_order_relaxed,
                                                    memory_order_relaxed))
        {
            // we managed to close the channel
            destroyContext(c);
            sendMessage(pl, finishRightSide, NULL, pl->left_tid, pl->right_tid);
            unlock(pl);
            return true;
        }
        // other line managed to close first and also queued us the fin packet
        return false;
    }

    assert(c->payload != NULL);
    sendMessage(pl, writeBufferToRightSide, c->payload, pl->left_tid, pl->right_tid);
    c->payload = NULL;
    destroyContext(c);

    return true;
}

bool writePipeLineRTL(pipe_line_t *pl, context_t *c)
{
    // other flags are not supposed to come to pipe line
    assert(c->fin || c->payload != NULL);

    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return false;
    }

    if (c->fin)
    {
        assert(pl->right_line);
        doneLineUpSide(pl->right_line);
        destroyLine(pl->right_line);
        pl->right_line = NULL;

        bool expected = false;

        if (atomic_compare_exchange_strong_explicit(&(pl->closed), &expected, true, memory_order_relaxed,
                                                    memory_order_relaxed))
        {
            // we managed to close the channel
            destroyContext(c);
            sendMessage(pl, finishLeftSide, NULL, pl->right_tid, pl->left_tid);
            unlock(pl);
            return true;
        }
        // other line managed to close first and also queued us the fin packet
        return false;
    }

    assert(c->payload != NULL);
    sendMessage(pl, writeBufferToLeftSide, c->payload, pl->right_tid, pl->left_tid);
    c->payload = NULL;
    destroyContext(c);

    return true;
}

void initRight(pipe_line_t *pl, void *arg)
{
    (void) arg;
    setupLineDownSide(pl->right_line, onRightLinePaused, pl, onRightLineResumed);
}
void initLeft(pipe_line_t *pl, void *arg)
{
    (void) arg;
    setupLineUpSide(pl->left_line, onLeftLinePaused, pl, onLeftLineResumed);
}

pipe_line_t *newPipeLineLeft(tunnel_t *self, uint8_t tid_left, line_t *left_line, uint8_t tid_right, line_t *right_line,
                             TunnelFlowRoutine local_up_stream, TunnelFlowRoutine local_down_stream)
{
    pipe_line_t *pl = malloc(sizeof(pipe_line_t));
    *pl             = (pipe_line_t){.self              = self,
                                    .left_tid          = tid_left,
                                    .right_tid         = tid_right,
                                    .left_line         = left_line,
                                    .right_line        = right_line,
                                    .closed            = false,
                                    .refc              = 1,
                                    .local_up_stream   = local_up_stream,
                                    .local_down_stream = local_down_stream};

    atomic_thread_fence(memory_order_release);
    initLeft(pl, NULL);
    sendMessage(pl, initRight, NULL, pl->left_tid, pl->right_tid);
    return pl;
}
pipe_line_t *newPipeLineRight(tunnel_t *self, uint8_t tid_left, line_t *left_line, uint8_t tid_right,
                              line_t *right_line, TunnelFlowRoutine local_up_stream,
                              TunnelFlowRoutine local_down_stream)
{
    pipe_line_t *pl = malloc(sizeof(pipe_line_t));
    *pl             = (pipe_line_t){.self              = self,
                                    .left_tid          = tid_left,
                                    .right_tid         = tid_right,
                                    .left_line         = left_line,
                                    .right_line        = right_line,
                                    .closed            = false,
                                    .refc              = 1,
                                    .local_up_stream   = local_up_stream,
                                    .local_down_stream = local_down_stream};

    atomic_thread_fence(memory_order_release);
    initRight(pl, NULL);
    sendMessage(pl, initLeft, NULL, pl->right_tid, pl->left_tid);
    return pl;
}
