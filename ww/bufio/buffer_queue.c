/**
 * @file buffer_queue.c
 * @brief Implementation of the buffer queue for managing sbuf_t buffers.
 */

#include "buffer_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

enum
{
    kQCapDefault = 8 // Initial capacity of the queue
};


/**
 * @brief Creates a new buffer queue.
 *
 * @param init_capacity The initial capacity for the queue.
 * @return A newly created buffer queue.
 */
buffer_queue_t bufferqueueCreate(int init_capacity)
{
    if (init_capacity < 1)
    {
        init_capacity = kQCapDefault;
    }

    buffer_queue_t bq = {.q = ww_sbuffer_queue_t_with_capacity(init_capacity)};
    return bq;
}

/**
 * @brief Destroys a buffer queue and releases its resources.
 * 
 * This function reuses all buffers in the queue before freeing the queue itself.
 *
 * @param self A pointer to the buffer queue to be destroyed.
 */
void bufferqueueDestory(buffer_queue_t *self)
{
    wid_t wid = getWID();
    c_foreach(i, ww_sbuffer_queue_t, self->q)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), *i.ref);
    }

    ww_sbuffer_queue_t_drop(&self->q);
}

/**
 * @brief Pushes an sbuf_t pointer onto the back of the queue.
 *
 * @param self A pointer to the buffer queue.
 * @param b A pointer to the sbuf_t to be added to the queue.
 */
void bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b)
{
    ww_sbuffer_queue_t_push_back(&self->q, b);
}

/**
 * @brief Pops an sbuf_t pointer from the front of the queue.
 *
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
sbuf_t *bufferqueuePopFront(buffer_queue_t *self)
{
    sbuf_t *b = ww_sbuffer_queue_t_pull_front(&self->q);
    return b;
}

/**
 * @brief Gets the sbuf_t pointer at the front of the queue without removing it.
 *
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
sbuf_t *bufferqueueFront(buffer_queue_t *self)
{
    return *ww_sbuffer_queue_t_front(&self->q);
}

/**
 * @brief Gets the number of elements in the queue.
 *
 * @param self A pointer to the buffer queue.
 * @return The number of sbuf_t pointers currently in the queue.
 */
size_t bufferqueueLen(buffer_queue_t *self)
{
    return (size_t)(ww_sbuffer_queue_t_size(&self->q));
}
