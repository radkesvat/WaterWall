#pragma once

#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

/*
    @brief A queue for sbuf_t pointers.

    This queue is designed to store sbuf_t pointers, providing a mechanism
    for managing and accessing these buffers in a FIFO (First-In-First-Out) manner.
    It's a simple queue implementation tailored for use with sbuf_t structures.
*/

typedef struct buffer_queue_s buffer_queue_t;

/*
    @brief Creates a new buffer queue.
    @param wid The worker ID associated with this queue.
    @return A pointer to the newly created buffer queue.
*/
buffer_queue_t *bufferqueueCreate(wid_t wid);

/*
    @brief Destroys a buffer queue and releases its resources.
    @param self A pointer to the buffer queue to be destroyed.
*/
void bufferqueueDestory(buffer_queue_t *self);

/*
    @brief Pushes an sbuf_t pointer onto the back of the queue.
    @param self A pointer to the buffer queue.
    @param b A pointer to the sbuf_t to be added to the queue.
*/
void bufferqueuePush(buffer_queue_t *self, sbuf_t *b);

/*
    @brief Pops an sbuf_t pointer from the front of the queue.
    @param self A pointer to the buffer queue.
    @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
*/
sbuf_t *bufferqueuePop(buffer_queue_t *self);

/*
    @brief Gets the number of elements in the queue.
    @param self A pointer to the buffer queue.
    @return The number of sbuf_t pointers currently in the queue.
*/
size_t bufferqueueLen(buffer_queue_t *self);
