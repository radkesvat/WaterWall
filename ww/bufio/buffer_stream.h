#pragma once
#include "wlibc.h"

#include "buffer_pool.h"
#include "shiftbuffer.h"

/*

    This implements a simple container that holds buffers, some opmizations are also applied.

    you can for example check byte index 1 or 5 of the buffers without concating them, then
    you'll be able to read only when your protocol is satisfied, the size you want


*/

#define i_type bs_doublequeue_t
#define i_key  sbuf_t *
#include "stc/deque.h"

struct buffer_stream_s
{
    buffer_pool_t   *pool;
    bs_doublequeue_t q;
    size_t           size;
    uint16_t         use_left_padding; // Whether to use left padding for buffers
};

typedef struct buffer_stream_s buffer_stream_t;

/**
 * Creates a new buffer stream.
 * @param pool The buffer pool.
 * @param use_left_padding Whether to use left padding for buffers.
 * @return A new buffer stream instance.
 */
buffer_stream_t bufferstreamCreate(buffer_pool_t *pool, uint16_t use_left_padding);

/**
 * Empties the buffer stream, returning all buffers to the pool.
 * @param self The buffer stream to empty.
 */
void bufferstreamEmpty(buffer_stream_t *self);

/**
 * Destroys the buffer stream and frees its resources.
 * @param self The buffer stream to destroy.
 */
void bufferstreamDestroy(buffer_stream_t *self);

/**
 * Pushes a buffer into the buffer stream.
 * @param self The buffer stream.
 * @param buf The buffer to push.
 */
void bufferstreamPush(buffer_stream_t *self, sbuf_t *buf);

/**
 * Reads an exact number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes);

/**
 * Reads at least a specified number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The minimum number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadAtLeast(buffer_stream_t *self, size_t bytes);

/**
 * Reads the ideal amount of data from the buffer stream.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamIdealRead(buffer_stream_t *self);

/**
 * Views a byte at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to view the byte.
 * @return The byte at the specified position.
 */
uint8_t bufferstreamViewByteAt(buffer_stream_t *self, size_t at);

/**
 * Views a sequence of bytes at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to start viewing the bytes.
 * @param buf The buffer to store the viewed bytes.
 * @param len The number of bytes to view.
 */
void bufferstreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len);

/**
 * Gets the length of the buffer stream.
 * @param self The buffer stream.
 * @return The length of the buffer stream.
 */
static inline size_t bufferstreamGetBufLen(buffer_stream_t *self)
{
    assert(self != NULL);
    return self->size;
}

/**
 * Reads the full length of the buffer stream.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
static inline sbuf_t *bufferstreamFullRead(buffer_stream_t *self)
{
    assert(self != NULL);
    return bufferstreamReadExact(self, bufferstreamGetBufLen(self));
}

/**
 * Checks if the buffer stream is empty.
 * @param self The buffer stream.
 * @return true if empty, false otherwise.
 */
static inline bool bufferstreamIsEmpty(buffer_stream_t *self)
{
    assert(self != NULL);
    return self->size == 0;
}
