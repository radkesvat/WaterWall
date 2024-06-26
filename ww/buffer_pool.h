#pragma once

#include "shiftbuffer.h"
#include <stdatomic.h>

/*
    A growable pool, very simple.

    preallocates (n) number of buffers at each call to charge(),
    
    users should call popBuffer() when they want a buffer, and later call reuseBuffer when they are done with
    the buffer.

    recharing is done autmatically and internally.

    - appendBufferMerge: concats 2 buffers to 1 in a efficient way, and the loser buffer is reused


    This is the most memory consuming part of the program, and also the preallocation length really
    depends on where you want to use this program, on a mobile phone or on a 16 core server?

    so the pool width is affected by ww memory profile

    for performance reasons, this pool dose not inherit from generic_pool, so 80% of the code is the same
    but also it has its own differences ofcourse
    
*/

struct buffer_pool_s;
typedef struct buffer_pool_s buffer_pool_t;

buffer_pool_t  *createSmallBufferPool(uint8_t tid);
buffer_pool_t  *createBufferPool(uint8_t tid);
shift_buffer_t *popBuffer(buffer_pool_t *pool);
void            reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b);
shift_buffer_t *appendBufferMerge(buffer_pool_t *pool, shift_buffer_t *restrict b1, shift_buffer_t *restrict b2);

// [not used] when you change the owner thread of a buffer, you should
// notify the original buffer pool that 1 buffer is lost form it
// this however, is not used
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
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
