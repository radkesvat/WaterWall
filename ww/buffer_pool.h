#pragma once

#include "shiftbuffer.h"
#ifdef DEBUG
#include "hv/hatomic.h"
#endif

typedef struct buffer_pool_s
{
    shift_buffer_t **available;
    size_t len;
#ifdef DEBUG
    _Atomic size_t in_use;
#endif
} buffer_pool_t;

buffer_pool_t *createBufferPool();
shift_buffer_t *popBuffer(buffer_pool_t *state);
void reuseBuffer(buffer_pool_t *state, shift_buffer_t *b);

#ifdef DEBUG
static inline void oneDetached(buffer_pool_t *state) { state->in_use -= 1; }
#else
static inline void oneDetached(buffer_pool_t *state) { (void *)state; }
#endif
