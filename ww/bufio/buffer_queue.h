/**
 * @file buffer_queue.h
 * @brief A FIFO queue implementation for managing sbuf_t buffers.
 */

#pragma once

#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

/**
 * @brief A queue for sbuf_t pointers.
 *
 * This queue is designed to store sbuf_t pointers, providing a mechanism
 * for managing and accessing these buffers in a FIFO (First-In-First-Out) manner.
 * It's a simple queue implementation tailored for use with sbuf_t structures.
 */


typedef struct buffer_queue_s buffer_queue_t;

#define i_type ww_sbuffer_queue_t
#define i_key  sbuf_t *
#include "stc/deque.h"

/**
 * @brief Structure representing a buffer queue.
 */
struct buffer_queue_s
{
    ww_sbuffer_queue_t q; // The internal queue data structure (internal)
    size_t total_len; // Total length of all buffers in the queue (optional, can be used for optimization)
};



/**
 * @brief Creates a new buffer queue.
 * 
 * @param init_capacity The initial capacity for the queue. If less than 1, a default value is used.
 * @return A newly created buffer queue.
 */
buffer_queue_t bufferqueueCreate(int init_capacity);

/**
 * @brief Destroys a buffer queue and releases its resources.
 * 
 * This function reuses all buffers in the queue before freeing the queue itself.
 * 
 * @param self A pointer to the buffer queue to be destroyed.
 */
void bufferqueueDestroy(buffer_queue_t *self);

/**
 * @brief Pushes an sbuf_t pointer onto the back of the queue.
 * 
 * @param self A pointer to the buffer queue.
 * @param b A pointer to the sbuf_t to be added to the queue.
 */
void bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b);

/**
 * @brief Pushes an sbuf_t pointer onto the front of the queue.
 * 
 * @param self A pointer to the buffer queue.
 * @param b A pointer to the sbuf_t to be added to the front of the queue.
 */
void bufferqueuePushFront(buffer_queue_t *self, sbuf_t *b);

/**
 * @brief Pops an sbuf_t pointer from the front of the queue.
 * 
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
sbuf_t *bufferqueuePopFront(buffer_queue_t *self);

/**
 * @brief Gets the sbuf_t pointer at the front of the queue without removing it.
 * 
 * @param self A pointer to the buffer queue.
 * @return A pointer to the sbuf_t at the front of the queue, or NULL if the queue is empty.
 */
const sbuf_t *bufferqueueFront(buffer_queue_t *self);

/**
 * @brief Gets the number of elements in the queue.
 * 
 * @param self A pointer to the buffer queue.
 * @return The number of sbuf_t pointers currently in the queue.
 */
size_t bufferqueueGetBufCount(buffer_queue_t *self);

/**
 * @brief Gets the total length of the sbuf_t pointers in the queue.
 *
 * @param self A pointer to the buffer queue.
 * @return The total length of the sbuf_t pointers currently in the queue.
 */
size_t bufferqueueGetBufLen(buffer_queue_t *self);
