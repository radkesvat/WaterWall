#pragma once

#include "shiftbuffer.h"
#ifdef DEBUG
#include "hv/hatomic.h"
#endif
struct buffer_pool_s
{
    shift_buffer_t **available;
    unsigned int     len;
#ifdef DEBUG
    atomic_size_t in_use;
#endif
};

typedef struct buffer_pool_s buffer_pool_t;

buffer_pool_t * createBufferPool();
shift_buffer_t *popBuffer(buffer_pool_t *state);
void            reuseBuffer(buffer_pool_t *state, shift_buffer_t *b);


// [not used] when you change the owner thread of a buffer, you should
// notify the original buffer pool that 1 buffer is lost form it
// this however, is not used
#ifdef DEBUG
static inline void notifyDetached(buffer_pool_t *state)
{
    state->in_use -= 1;
}
#else
static inline void notifyDetached(buffer_pool_t *state)
{
    (void) state;
}
#endif
