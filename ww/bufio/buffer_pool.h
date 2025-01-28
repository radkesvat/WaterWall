#pragma once
#include "generic_pool.h"
#include "master_pool.h"
#include "shiftbuffer.h"
#include "wlibc.h"

/*
    A growable pool

    preallocates (n) number of buffers at each call to charge(),

    users should call bufferpoolGetLargeBuffer() when they want a buffer, and later call bufferpoolResuesBuffer when
   they are done with the buffer.

    recharing is done autmatically and internally.

    This is the most memory consuming part of the program, and also the preallocation length really
    depends on where you want to use this program, on a mobile phone or on a 16 core server?

    so the pool width is affected by ww memory profile

    for performance reasons, this pool dose not inherit from generic_pool, so 80% of the code is the same
    but also it has its own differences ofcourse

*/

typedef struct buffer_pool_s buffer_pool_t;

buffer_pool_t *bufferpoolCreate(struct master_pool_s *mp_large, struct master_pool_s *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size);
sbuf_t        *bufferpoolGetLargeBuffer(buffer_pool_t *pool);
sbuf_t        *bufferpoolGetSmallBuffer(buffer_pool_t *pool);
void           bufferpoolResuesBuffer(buffer_pool_t *pool, sbuf_t *b);

void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding);

uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool);
uint32_t bufferpoolGetSmallBufferSize(buffer_pool_t *pool);
bool     bufferpoolCheckIskLargeBuffer(sbuf_t *buf);

sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);
sbuf_t *sbufAppendMergeNoPadding(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2);
sbuf_t *sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *b);
