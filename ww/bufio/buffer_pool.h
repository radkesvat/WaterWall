#pragma once
#include "master_pool.h"
#include "generic_pool.h"
#include "shiftbuffer.h"
#include "wlibc.h"

/*
    A growable pool

    preallocates (n) number of buffers at each call to charge(),

    users should call bufferpoolGetLargeBuffer() when they want a buffer, and later call bufferpoolReuseBuffer when
    they are done with the buffer.

    recharing is done autmatically and internally.

    This is the most memory consuming part of the program, and also the preallocation length really
    depends on where you want to use this program, on a mobile phone or on a 16 core server?

    so the pool width is affected by ww memory profile

    for performance reasons, this pool dose not inherit from generic_pool, so 80% of the code is the same
    but also it has its own differences ofcourse

*/

typedef struct buffer_pool_s buffer_pool_t;

/**
 * Creates a buffer pool with specified parameters.
 * @param mp_large The master pool for large buffers.
 * @param mp_small The master pool for small buffers.
 * @param bufcount The number of buffers to preallocate.
 * @param large_buffer_size The size of each large buffer.
 * @param small_buffer_size The size of each small buffer.
 * @return A pointer to the created buffer pool.
 */
buffer_pool_t *bufferpoolCreate(master_pool_t *mp_large, master_pool_t *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size);

void bufferpoolDestroy(buffer_pool_t *pool);

/**
 * Retrieves a large buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved large buffer.
 */
sbuf_t *bufferpoolGetLargeBuffer(buffer_pool_t *pool);

/**
 * Retrieves a small buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved small buffer.
 */
sbuf_t *bufferpoolGetSmallBuffer(buffer_pool_t *pool);

/**
 * Reuses a buffer by returning it to the buffer pool.
 * @param pool The buffer pool.
 * @param b The buffer to reuse.
 */
void bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

/**
 * Updates the allocation paddings for the buffer pool.
 * @param pool The buffer pool.
 * @param large_buffer_left_padding The left padding for large buffers.
 * @param small_buffer_left_padding The left padding for small buffers.
 */
void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding);

/**
 * Gets the size of large buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of large buffers.
 */
uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool);
uint16_t bufferpoolGetLargeBufferPadding(buffer_pool_t *pool);


/**
 * Gets the size of small buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of small buffers.
 */
uint32_t bufferpoolGetSmallBufferSize(buffer_pool_t *pool);
uint16_t bufferpoolGetSmallBufferPadding(buffer_pool_t *pool);

/**
 * Checks if a buffer is a large buffer.
 * @param buf The buffer to check.
 * @return True if the buffer is a large buffer, false otherwise.
 */
bool bufferpoolCheckIskLargeBuffer(sbuf_t *buf);

/**
 * Appends and merges two buffers.
 * @param pool The buffer pool.
 * @param b1 The first buffer.
 * @param b2 The second buffer.
 * @return A pointer to the merged buffer.
 */
sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);

/**
 * Duplicates a buffer using the buffer pool.
 * @param pool The buffer pool.
 * @param b The buffer to duplicate.
 * @return A pointer to the duplicated buffer.
 */
sbuf_t *sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *b);
