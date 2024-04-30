#pragma once

#include "shiftbuffer.h"
#include <stdatomic.h>

/*
    Just do a big memory allocation at the startup and keep using them, don't talk to os as much as possible.
    it can also grow up (allocate another big chunk) and shrink down to the first state

    This is the most memory consuming part of the program, and also the preallocation length really
    depends on where you want to use this program, on a phone or on a 16 core server?
    so there are possible choices for memory profiles in the .c file which you can select the best for your needs

    todo (runtime selection) its better that the memory profile be a runtime selection than compile time

*/

struct buffer_pool_s
{
    unsigned int len;
    unsigned int cap;
    unsigned int free_threshould;
    unsigned int buffers_size;
#ifdef DEBUG
    atomic_size_t in_use;
#endif
    shift_buffer_t *available[];
};

typedef struct buffer_pool_s buffer_pool_t;

buffer_pool_t  *createSmallBufferPool();
buffer_pool_t  *createBufferPool();
shift_buffer_t *popBuffer(buffer_pool_t *pool);
void            reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b);
shift_buffer_t *appendBufferMerge(buffer_pool_t *pool, shift_buffer_t *restrict b1, shift_buffer_t *restrict b2);

// [not used] when you change the owner thread of a buffer, you should
// notify the original buffer pool that 1 buffer is lost form it
// this however, is not used
#ifdef DEBUG
static inline void notifyDetached(buffer_pool_t *pool)
{
    pool->in_use -= 1;
}
#else
static inline void notifyDetached(buffer_pool_t *pool)
{
    (void) pool;
}
#endif
