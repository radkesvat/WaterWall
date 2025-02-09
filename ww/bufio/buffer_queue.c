#include "buffer_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

#define i_type queue_t
#define i_key  sbuf_t *
#include "stc/deque.h"

enum
{
    kQCap = 8 // Initial capacity of the queue
};

struct buffer_queue_s
{
    queue_t q;   // The internal queue data structure
    wid_t   wid; // Worker ID associated with this queue
};

/*
    @brief Creates a new buffer queue.
    @param wid The worker ID associated with this queue.
    @return A pointer to the newly created buffer queue.
*/
buffer_queue_t *bufferqueueCreate(wid_t wid)
{
    buffer_queue_t *cb = memoryAllocate(sizeof(buffer_queue_t));
    cb->q              = queue_t_with_capacity(kQCap);
    cb->wid            = wid;
    return cb;
}

/*
    @brief Destroys a buffer queue and releases its resources.
    This function reuses all buffers in the queue before freeing the queue itself.
    @param self A pointer to the buffer queue to be destroyed.
*/
void bufferqueueDestory(buffer_queue_t *self)
{
    c_foreach(i, queue_t, self->q)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(self->wid), *i.ref);
    }

    queue_t_drop(&self->q);
    memoryFree(self);
}

/*
    @brief Pushes an sbuf_t pointer onto the back of the queue.
    @param self A pointer to the buffer queue.
    @param b A pointer to the sbuf_t to be added to the queue.
*/
void bufferqueuePush(buffer_queue_t *self, sbuf_t *b)
{
    queue_t_push_back(&self->q, b);
}

/*
    @brief Pops an sbuf_t pointer from the front of the queue.
    @param self A pointer to the buffer queue.
    @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
*/
sbuf_t *bufferqueuePop(buffer_queue_t *self)
{
    sbuf_t *b = queue_t_pull_front(&self->q);
    return b;
}

/*
    @brief Gets the number of elements in the queue.
    @param self A pointer to the buffer queue.
    @return The number of sbuf_t pointers currently in the queue.
*/
size_t bufferqueueLen(buffer_queue_t *self)
{
    return queue_t_size(&self->q);
}
