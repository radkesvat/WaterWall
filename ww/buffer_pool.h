#pragma once

#include "shiftbuffer.h"


typedef struct buffer_pool_s
{
    shift_buffer_t** available;
    size_t len;
    size_t in_use;
    size_t chunks;
} buffer_pool_t;



buffer_pool_t* createBufferPool();
shift_buffer_t* popBuffer(buffer_pool_t* state);
void reuseBuffer(buffer_pool_t*state,shift_buffer_t* b);



