#pragma once

/*
 * Buffer pool for ordinary small/medium/large buffers and dedicated splice wrappers.
 */

#include "generic_pool.h"
#include "master_pool.h"
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
 * @param mp_medium The master pool for medium helper buffers.
 * @param mp_small The master pool for small buffers.
 * @param mp_splice The master pool for splice wrappers, with 32 bytes of control storage.
 * @param bufcount The number of buffers to preallocate.
 * @param large_buffer_size The size of each large buffer.
 * @param medium_buffer_size The size of each medium helper buffer.
 * @param small_buffer_size The size of each small buffer.
 * @return A pointer to the completely constructed buffer pool, or NULL when
 *         the input geometry, any master pool, or any metadata allocation
 *         cannot be satisfied. Nothing is published and no master-pool
 *         callback is installed on failure.
 */
buffer_pool_t *bufferpoolCreate(master_pool_t *mp_large, master_pool_t *mp_medium, master_pool_t *mp_small,
                                master_pool_t *mp_splice, uint32_t bufcount, uint32_t large_buffer_size,
                                uint32_t medium_buffer_size, uint32_t small_buffer_size);

/**
 * @brief Destroy a buffer pool and free all pooled buffers.
 *
 * @param pool Buffer pool instance.
 */
void bufferpoolDestroy(buffer_pool_t *pool);

/**
 * Retrieves a large buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved large buffer.
 */
sbuf_t *bufferpoolGetLargeBuffer(buffer_pool_t *pool);

/** Retrieve a medium helper buffer (32 KiB in S1/S2, 64 KiB in higher profiles).
 * Cache counts follow the pool width;
 * event-loop reads continue to request large buffers explicitly. */
sbuf_t  *bufferpoolGetMediumBuffer(buffer_pool_t *pool);
uint32_t bufferpoolGetMediumBufferSize(buffer_pool_t *pool);
uint16_t bufferpoolGetMediumBufferPadding(buffer_pool_t *pool);

/**
 * Retrieves a small buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved small buffer.
 */
sbuf_t *bufferpoolGetSmallBuffer(buffer_pool_t *pool);

/** Retrieve an empty splice wrapper with kSbufFlagSplice set, 32 bytes of control storage, and reserved left padding.
 * Its private pipe is uninitialized or empty. Populate the pipe before publishing its actual logical body size. */
sbuf_t *bufferpoolGetSpliceBuffer(buffer_pool_t *pool);

/**
 * Retrieve the smallest small/medium/large pooled buffer satisfying both payload capacity
 * and left-padding requirements. Splice allocation is explicit. When no
 * ordinary tier fits, allocate a dedicated
 * padded buffer; bufferpoolReuseBuffer() safely destroys that fallback.
 *
 * @param pool Buffer pool instance.
 * @param minimum_payload Minimum writable payload capacity in bytes.
 * @param minimum_left_padding Minimum left padding in bytes.
 * @return A reset owned buffer satisfying both requirements.
 */
sbuf_t *bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t minimum_payload, uint16_t minimum_left_padding);

/** Checked best-fit allocation for wide computed lengths. Returns NULL for
 * unrepresentable geometry; otherwise uses the same pooled tiers as GetBestFit. */
sbuf_t *bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t minimum_payload, uint16_t minimum_left_padding);

/**
 * Reuses a buffer by returning it to the buffer pool.
 * Takes ownership and discards remaining payload, including a splice wrapper's
 * real prefix and private-pipe body. Splice discard runs in every build, including
 * when pooling is bypassed. With BUFFER_POOL_DEBUG == 1, kernel-emptiness validation
 * logs a fatal error and aborts on failure before reset, independently of NDEBUG.
 * Healthy empty pairs survive reuse; a drain failure closes the pair.
 * Callers must exclusively own the buffer.
 * @param pool The buffer pool.
 * @param b The buffer to reuse.
 */
void bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

/**
 * Releases the pool's debug thread ownership after its owning thread has been
 * joined. The next accessor becomes the new owner.
 *
 * The caller must have exclusive access to the pool. In particular, this must
 * not be used as a way to move a live pool between concurrent threads.
 *
 * @param pool Buffer pool whose former owner can no longer access it.
 */
void bufferpoolResetThreadOwnership(buffer_pool_t *pool);

/**
 * Updates the allocation paddings for the buffer pool.
 * @param pool The buffer pool.
 * @param large_buffer_left_padding The left padding for large buffers.
 * @param medium_buffer_left_padding The left padding for medium buffers.
 * @param small_buffer_left_padding The left padding for small buffers.
 * @param splice_buffer_left_padding The left padding for splice buffers.
 */
void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t medium_buffer_left_padding, uint16_t small_buffer_left_padding,
                                        uint16_t splice_buffer_left_padding);

/**
 * Gets the size of large buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of large buffers.
 */
uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool);

/**
 * @brief Get configured left padding for large buffers.
 *
 * @param pool Buffer pool instance.
 * @return uint16_t Left padding in bytes.
 */
uint16_t bufferpoolGetLargeBufferPadding(buffer_pool_t *pool);

/**
 * Gets the size of small buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of small buffers.
 */
uint32_t bufferpoolGetSmallBufferSize(buffer_pool_t *pool);

/**
 * @brief Get configured left padding for small buffers.
 *
 * @param pool Buffer pool instance.
 * @return uint16_t Left padding in bytes.
 */
uint16_t bufferpoolGetSmallBufferPadding(buffer_pool_t *pool);

/** Return the fixed 32-byte control-storage capacity, excluding padding and logical payload size. */
uint32_t bufferpoolGetSpliceBufferStorageSize(buffer_pool_t *pool);

/** Return the pool's configured splice left padding. */
uint16_t bufferpoolGetSpliceBufferPadding(buffer_pool_t *pool);

/**
 * Checks if a buffer is a large buffer.
 * @param buf The buffer to check.
 * @return True if the buffer is a large buffer, false otherwise.
 */
bool bufferpoolCheckIsLargeBuffer(sbuf_t *buf);

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
