#pragma once

#include "shiftbuffer.h"


typedef struct buffer_dispatcher_storage_s
{
    shift_buffer_t** available;
    size_t len;
    size_t in_use;
    size_t chunks;
} buffer_dispatcher_storage_t;



buffer_dispatcher_storage_t* createBufferDispatcher();
shift_buffer_t* popShiftBuffer(buffer_dispatcher_storage_t* state);
void reuseShiftBuffer(buffer_dispatcher_storage_t*state,shift_buffer_t* b);



