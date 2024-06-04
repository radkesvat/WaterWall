#include "pipe_line.h"
#include "hmutex.h"
#include "hplatform.h"
#include "tunnel.h"
#include <stdatomic.h>
#include <stdint.h>

struct msg_event
{
    pipe_line_t *pl;
    void        *function;
    void        *arg;
};

typedef void (*MsgTargetFunction)(pipe_line_t *pl, void *arg);

static void onMsgReceived(hevent_t *ev)
{
    struct msg_event *msg_ev = hevent_userdata(ev);
    (*(MsgTargetFunction *) (&(msg_ev->function)))(msg_ev->pl, msg_ev->arg);
    free(msg_ev);
}

static void sendMessage(pipe_line_t *pl, MsgTargetFunction fn, void *arg, uint8_t tid_from, uint8_t tid_to)
{
    if (tid_from == tid_to)
    {
        fn(pl, arg);
        return;
    }

    struct msg_event *evdata = malloc(sizeof(struct msg_event));
    *evdata                  = (struct msg_event){.pl = pl, .function = *(void **) (&fn), .arg = arg};

    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = loops[tid_to];
    ev.cb   = onMsgReceived;
    hevent_set_userdata(&ev, evdata);
    hloop_post_event(loops[tid_to], &ev);
}

void finishLeftSide(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->left_line == NULL)
    {
        return;
    }
    context_t *fctx = newFinContext(pl->left_line);
    // doneLineDownSide(pl->left_line);
    // destroyLine(pl->left_line);
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
    // doneLineUpSide(pl->right_line);
    // destroyLine(pl->right_line);
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

void onLeftLinePaused(pipe_line_t *pl, void *arg)
{
    (void) arg;
    sendMessage(pl, pauseRightLine, NULL, pl->left_tid, pl->right_tid);
}

void onRightLinePaused(pipe_line_t *pl, void *arg)
{
    (void) arg;
    sendMessage(pl, pauseLeftLine, NULL, pl->right_tid, pl->left_tid);
}

void onLeftLineResumed(pipe_line_t *pl, void *arg)
{
    (void) arg;
    sendMessage(pl, resumeRightLine, NULL, pl->left_tid, pl->right_tid);
}

void onRightLineResumed(pipe_line_t *pl, void *arg)
{
    (void) arg;
    sendMessage(pl, pauseLeftLine, NULL, pl->right_tid, pl->left_tid);
}

bool writePipeLineLTR(pipe_line_t *pl, context_t *c)
{
    // other flags are not supposed to come to pipe line
    assert(c->fin || c->payload != NULL);

    atomic_compare_exchange_strong_explicit
    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return false;
    }

    if (c->fin)
    {
        atomic_store_explicit(&pl->closed, true, memory_order_relaxed);
        destroyLine(pl->left_line);
        pl->left_line = NULL;
        destroyLine(line_t *l)
    }
    else 
    {
        assert(c->payload != NULL);

    }

    if (pl->direct_mode)
    {
        // c = switchLine(c, pl->right_line);

        pl->self->up->upStream(pl->self->up, c);

        return true;
    }

    return true;
}

bool writePipeLineRTL(pipe_line_t *p, context_t *c)
{
}

pipe_line_t *newPipeLine(uint8_t tid_left, uint8_t tid_right);
void         freePipeLine(pipe_line_t *p);
