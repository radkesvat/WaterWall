#include "buffer_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

#define i_type queue_t
#define i_key  sbuf_t *
#include "stc/deque.h"

enum
{
    kQCap = 8
};

struct buffer_queue_s
{
    queue_t q;
    wid_t wid;
};

buffer_queue_t *bufferqueueCreate(wid_t wid)
{
    buffer_queue_t *cb = memoryAllocate(sizeof(buffer_queue_t));
    cb->q              = queue_t_with_capacity(kQCap);
    cb->wid            = wid;
    return cb;
}

void bufferqueueDestory(buffer_queue_t *self)
{
    c_foreach(i, queue_t, self->q)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(self->wid),*i.ref);
    }

    queue_t_drop(&self->q);
    memoryFree(self);
}

void bufferqueuePush(buffer_queue_t *self, sbuf_t *b)
{
    queue_t_push_back(&self->q, b);
}

sbuf_t *bufferqueuePop(buffer_queue_t *self)
{
    sbuf_t *b = queue_t_pull_front(&self->q);
    return b;
}

size_t bufferqueueLen(buffer_queue_t *self)
{
    return queue_t_size(&self->q);
}
