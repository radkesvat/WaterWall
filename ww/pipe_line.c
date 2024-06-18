#include "pipe_line.h"
#include "buffer_pool.h"
#include "generic_pool.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "ww.h"

struct pipe_line_s
{
    atomic_bool         closed;
    atomic_int          refc;
    bool                first_sent;
    uint8_t             left_tid;
    uint8_t             right_tid;
    uintptr_t           memptr;
    tunnel_t           *self;
    line_t             *left_line;
    line_t             *right_line;
    PipeLineFlowRoutine local_up_stream;
    PipeLineFlowRoutine local_down_stream;

} ATTR_ALIGNED_LINE_CACHE;

struct msg_event
{
    pipe_line_t *pl;
    void        *function;
    void        *arg;
    uint8_t      target_tid;
};

typedef void (*MsgTargetFunction)(pipe_line_t *pl, void *arg);

pool_item_t *allocPipeLineMsgPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return malloc(sizeof(struct msg_event));
}

void destroyPipeLineMsgPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    free(item);
}

static void lock(pipe_line_t *pl)
{
    // int old_refc = atomic_fetch_add_explicit(&pl->refc, 1, memory_order_release);
    int old_refc = atomic_fetch_add_explicit(&pl->refc, 1, memory_order_relaxed);
    if (0 >= old_refc)
    {
        // this should not happen, otherwise we must change memory order
        // but i think its ok because threads synchronize around the mutex in eventloop
        LOGF("PipeLine: thread-safety done incorrectly lock()");
        exit(1);
    }
}

static void unlock(pipe_line_t *pl)
{
    // int old_refc = atomic_fetch_add_explicit(&pl->refc, -1, memory_order_acquire);
    int old_refc = atomic_fetch_add_explicit(&pl->refc, -1, memory_order_relaxed);
    if (old_refc == 1)
    {
        if (! atomic_load_explicit(&(pl->closed), memory_order_relaxed))
        {
            // this should not happen, otherwise we must change memory order
            // but i think its ok because threads synchronize around the mutex in eventloop
            LOGF("PipeLine: thread-safety done incorrectly unlock()");
            exit(1);
        }
        free((void *) pl->memptr); // NOLINT
    }
}

static void onMsgReceived(hevent_t *ev)
{
    struct msg_event *msg_ev = hevent_userdata(ev);
    pipe_line_t      *pl     = msg_ev->pl;
    (*(MsgTargetFunction *) (&(msg_ev->function)))(pl, msg_ev->arg);
    reusePoolItem(pipeline_msg_pools[msg_ev->target_tid], msg_ev);
    unlock(pl);
}

static void sendMessage(pipe_line_t *pl, MsgTargetFunction fn, void *arg, uint8_t tid_from, uint8_t tid_to)
{

    if (tid_from == tid_to)
    {
        fn(pl, arg);
        return;
    }
    lock(pl);
    struct msg_event *evdata = popPoolItem(pipeline_msg_pools[tid_from]);
    *evdata                  = (struct msg_event){.pl = pl, .function = *(void **) (&fn), .arg = arg,.target_tid=tid_to};

    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = loops[tid_to];
    ev.cb   = onMsgReceived;
    hevent_set_userdata(&ev, evdata);
    hloop_post_event(loops[tid_to], &ev);
}

static void writeBufferToLeftSide(pipe_line_t *pl, void *arg)
{
    shift_buffer_t *buf = arg;
    if (pl->right_line == NULL)
    {
        reuseBuffer(buffer_pools[pl->left_tid], buf);
        return;
    }
    context_t *ctx = newContext(pl->left_line);
    ctx->payload   = buf;
    pl->local_down_stream(pl->self, ctx, pl);
}

static void writeBufferToRightSide(pipe_line_t *pl, void *arg)
{
    shift_buffer_t *buf = arg;
    if (pl->right_line == NULL)
    {
        reuseBuffer(buffer_pools[pl->right_tid], buf);
        return;
    }
    context_t *ctx = newContext(pl->right_line);
    ctx->payload   = buf;
    if (WW_UNLIKELY(! pl->first_sent))
    {
        pl->first_sent = true;
        ctx->first     = true;
    }
    pl->local_up_stream(pl->self, ctx, pl);
}

static void finishLeftSide(pipe_line_t *pl, void *arg)
{
    (void) arg;

    if (pl->left_line == NULL)
    {
        return;
    }
    context_t *fctx = newFinContext(pl->left_line);
    doneLineUpSide(pl->left_line);
    // destroyLine(pl->left_line);
    pl->left_line = NULL;
    pl->local_down_stream(pl->self, fctx, pl);
    unlock(pl);
}

static void finishRightSide(pipe_line_t *pl, void *arg)
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
    pl->local_up_stream(pl->self, fctx, pl);
    unlock(pl);
}

static void pauseLeftLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->left_line == NULL)
    {
        return;
    }
    pauseLineDownSide(pl->left_line);
}

static void pauseRightLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->right_line == NULL)
    {
        return;
    }
    pauseLineUpSide(pl->right_line);
}

static void resumeLeftLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->left_line == NULL)
    {
        return;
    }
    resumeLineDownSide(pl->left_line);
}

static void resumeRightLine(pipe_line_t *pl, void *arg)
{
    (void) arg;
    if (pl->right_line == NULL)
    {
        return;
    }
    resumeLineUpSide(pl->right_line);
}

void pipeOnUpLinePaused(void *state)
{
    pipe_line_t *pl = state;
    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return;
    }
    sendMessage(pl, pauseLeftLine, NULL, pl->right_tid, pl->left_tid);
}

void pipeOnUpLineResumed(void *state)
{
    pipe_line_t *pl = state;
    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return;
    }
    sendMessage(pl, resumeLeftLine, NULL, pl->right_tid, pl->left_tid);
}

void pipeOnDownLinePaused(void *state)
{
    pipe_line_t *pl = state;
    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return;
    }
    sendMessage(pl, pauseRightLine, NULL, pl->left_tid, pl->right_tid);
}

void pipeOnDownLineResumed(void *state)
{

    pipe_line_t *pl = state;
    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return;
    }
    sendMessage(pl, resumeRightLine, NULL, pl->left_tid, pl->right_tid);
}

bool pipeUpStream(pipe_line_t *pl, context_t *c)
{
    // other flags are not supposed to come to pipe line
    assert(c->fin || c->payload != NULL);
    assert(pl->left_line);

    if (c->fin)
    {
        doneLineUpSide(pl->left_line);
        // destroyLine(pl->left_line);
        pl->left_line = NULL;

        bool expected = false;

        if (atomic_compare_exchange_strong_explicit(&(pl->closed), &expected, true, memory_order_relaxed,
                                                    memory_order_relaxed))
        {
            // we managed to close the channel
            destroyContext(c);
            sendMessage(pl, finishRightSide, NULL, pl->left_tid, pl->right_tid);
            return true;
        }
        // other line managed to close first and also queued us the fin packet
        return false;
    }

    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return false;
    }
    assert(c->payload != NULL);
    sendMessage(pl, writeBufferToRightSide, c->payload, pl->left_tid, pl->right_tid);
    c->payload = NULL;
    destroyContext(c);

    return true;
}

bool pipeDownStream(pipe_line_t *pl, context_t *c)
{
    // est context is ignored, only fin or data makes sense
    // if (WW_UNLIKELY(c->est))
    // {
    //     destroyContext(c);
    //     return true;
    // }
    assert(! c->est);

    // other flags are not supposed to come to pipe line
    assert(c->fin || c->payload != NULL);
    assert(pl->right_line);

    if (c->fin)
    {
        doneLineDownSide(pl->right_line);
        destroyLine(pl->right_line);
        pl->right_line = NULL;

        bool expected = false;

        if (atomic_compare_exchange_strong_explicit(&(pl->closed), &expected, true, memory_order_relaxed,
                                                    memory_order_relaxed))
        {
            // we managed to close the channel
            destroyContext(c);
            sendMessage(pl, finishLeftSide, NULL, pl->right_tid, pl->left_tid);
            return true;
        }
        // other line managed to close first and also queued us the fin packet
        return false;
    }

    if (atomic_load_explicit(&pl->closed, memory_order_relaxed))
    {
        return false;
    }
    assert(c->payload != NULL);
    sendMessage(pl, writeBufferToLeftSide, c->payload, pl->right_tid, pl->left_tid);
    c->payload = NULL;
    destroyContext(c);

    return true;
}

static void initRight(pipe_line_t *pl, void *arg)
{
    (void) arg;
    pl->right_line = newLine(pl->right_tid);
    setupLineDownSide(pl->right_line, pipeOnUpLinePaused, pl, pipeOnUpLineResumed);
    context_t *context = newInitContext(pl->right_line);
    pl->local_up_stream(pl->self, context, pl);

    // lockLine(pl->right_line);
}

static void initLeft(pipe_line_t *pl, void *arg)
{
    (void) arg;
    setupLineUpSide(pl->left_line, pipeOnDownLinePaused, pl, pipeOnDownLineResumed);
}

void newPipeLine(pipe_line_t **result, tunnel_t *self, uint8_t this_tid, line_t *left_line, uint8_t dest_tid,
                 PipeLineFlowRoutine local_up_stream, PipeLineFlowRoutine local_down_stream)

{
    assert(*result == NULL);

    assert(sizeof(struct pipe_line_s) <= kCpuLineCacheSize);
    int64_t memsize = (int64_t) sizeof(struct pipe_line_s);
    // ensure we have enough space to offset the allocation by line cache (for alignment)
    MUSTALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < (int64_t) sizeof(struct pipe_line_s))
    {
        fprintf(stderr, "buffer size out of range");
        exit(1);
    }

    // allocate memory, placing pipe_line_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) malloc(memsize);

    // align c to line cache boundary
    MUSTALIGN2(ptr, kCpuLineCacheSize);

    pipe_line_t *pl = (pipe_line_t *) ALIGN2(ptr, kCpuLineCacheSize); // NOLINT
    *pl             = (pipe_line_t){.memptr            = ptr,
                                    .self              = self,
                                    .left_tid          = this_tid,
                                    .right_tid         = dest_tid,
                                    .left_line         = left_line,
                                    .right_line        = NULL,
                                    .closed            = false,
                                    .first_sent        = false,
                                    .refc              = 1,
                                    .local_up_stream   = local_up_stream,
                                    .local_down_stream = local_down_stream};
    *result         = pl;

    initLeft(pl, NULL);
    sendMessage(pl, initRight, NULL, pl->left_tid, pl->right_tid);
}
