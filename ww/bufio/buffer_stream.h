#pragma once

/*
 * Stream-like container for staged reads over queued pooled buffers.
 */

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
    uint16_t         use_left_padding; // Exact left-padding budget consumed by split exact-read allocations
};

typedef struct buffer_stream_s buffer_stream_t;

/**
 * Creates a new buffer stream.
 * @param pool The buffer pool.
 * @param use_left_padding Exact number of left-padding bytes that a split
 *        exact-read allocation may consume. The caller's chain must guarantee
 *        this budget on the large tier; the small tier is used only when its
 *        configured padding also provides the complete budget.
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
 * Pushes ordered bytes, possibly coalescing the complete input into the current tail.
 * Ownership transfers on every path; an eligible input may be recycled before
 * return. Never access the source or pointers into it after transfer, or rely on
 * allocation identity or one retained chunk per push. Payload contents and FIFO
 * byte order are preserved; coalescing is permitted, not guaranteed.
 * The current policy copies only positive inputs of at most 4096 bytes that fit
 * wholly in the tail's actual spare capacity, excluding temporary buffers and
 * lifetime metadata on either allocation. It never grows or compacts the tail,
 * searches older entries, partially merges, or consumes left padding. The tail
 * can exceed 4096 bytes. Empty inputs are enqueued; an eligible empty tail can
 * absorb later input. Coalescing does not replace byte limits or backpressure.
 * @param self The buffer stream.
 * @param buf The buffer whose ownership transfers to the stream.
 */
void bufferstreamPush(buffer_stream_t *self, sbuf_t *buf);

/**
 * Reads exactly the next bytes, combining or splitting storage as needed.
 * Requires 0 < bytes <= buffered length. Neither allocation identity nor original
 * push boundaries are guaranteed. Split allocations use the configured
 * use_left_padding budget and a pool tier providing that complete budget.
 * @param self The buffer stream.
 * @param bytes The number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes);

/**
 * Reads at least the next bytes, possibly more according to internal chunking.
 * Requires 0 < bytes <= buffered length; original push boundaries do not define
 * the returned size.
 * @param self The buffer stream.
 * @param bytes The minimum number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadAtLeast(buffer_stream_t *self, size_t bytes);

/**
 * Transfers a queued internal storage chunk efficiently, not a pushed chunk or
 * protocol record. Requires positive buffered byte length; a retained empty
 * entry can still produce a zero-length result.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamIdealRead(buffer_stream_t *self);

/**
 * Views a byte at a valid position, independent of internal byte partitioning.
 *
 * The caller must provide a non-NULL stream and guarantee
 * `at < bufferstreamGetBufLen(self)`. Violating this precondition, or detecting
 * inconsistent internal size accounting, terminates the program in every build.
 *
 * @param self The non-NULL buffer stream.
 * @param at A valid byte position smaller than the stream length.
 * @return The byte at the specified position.
 */
uint8_t bufferstreamViewByteAt(buffer_stream_t *self, size_t at);

/**
 * Views ordered bytes at a position, independent of internal byte partitioning.
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
 * Reads all buffered bytes, or returns NULL for zero logical bytes. This is not a record parser.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
static inline sbuf_t *bufferstreamFullRead(buffer_stream_t *self)
{
    assert(self != NULL);
    size_t bytes = bufferstreamGetBufLen(self);
    if (bytes == 0)
    {
        return NULL;
    }
    return bufferstreamReadExact(self, bytes);
}

/**
 * Checks logical byte emptiness. Retained empty entries still require cleanup.
 * @param self The buffer stream.
 * @return true if empty, false otherwise.
 */
static inline bool bufferstreamIsEmpty(buffer_stream_t *self)
{
    assert(self != NULL);
    return self->size == 0;
}

/* Delimiter searches observe ordered bytes independently of internal chunk boundaries. */
static inline bool bufferstreamFindCRLF(buffer_stream_t *stream, size_t *line_end)
{
    if (bufferstreamGetBufLen(stream) < 2)
    {
        return false;
    }

    int    state      = 0;
    size_t match_idx  = 0;
    size_t cur_offset = 0;

    c_foreach(qi, bs_doublequeue_t, stream->q)
    {
        sbuf_t  *b      = *qi.ref;
        size_t   b_size = sbufGetLength(b);
        uint8_t *b_data = (uint8_t *) sbufGetRawPtr(b);

        for (size_t i = 0; i < b_size; ++i)
        {
            uint8_t c = b_data[i];

            if (state == 0)
            {
                if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
            }
            else if (state == 1)
            {
                if (c == '\n')
                {
                    *line_end = match_idx;
                    return true;
                }
                if (c == '\r')
                {
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
        }
        cur_offset += b_size;
    }

    return false;
}

static inline bool bufferstreamFindDoubleCRLF(buffer_stream_t *stream, size_t *header_end)
{
    if (bufferstreamGetBufLen(stream) < 4)
    {
        return false;
    }

    int    state      = 0;
    size_t match_idx  = 0;
    size_t cur_offset = 0;

    c_foreach(qi, bs_doublequeue_t, stream->q)
    {
        sbuf_t  *b      = *qi.ref;
        size_t   b_size = sbufGetLength(b);
        uint8_t *b_data = (uint8_t *) sbufGetRawPtr(b);

        for (size_t i = 0; i < b_size; ++i)
        {
            uint8_t c = b_data[i];

            if (state == 0)
            {
                if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
            }
            else if (state == 1)
            {
                if (c == '\n')
                {
                    state = 2;
                }
                else if (c == '\r')
                {
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
            else if (state == 2)
            {
                if (c == '\r')
                {
                    state = 3;
                }
                else
                {
                    state = 0;
                }
            }
            else if (state == 3)
            {
                if (c == '\n')
                {
                    *header_end = match_idx + 4U;
                    return true;
                }
                if (c == '\r')
                {
                    state     = 1;
                    match_idx = cur_offset + i;
                }
                else
                {
                    state = 0;
                }
            }
        }
        cur_offset += b_size;
    }

    return false;
}
