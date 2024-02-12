#pragma once

#include "shiftbuffer.h"


struct buffer_dispatcher_storage_s
{
    shift_buffer_t** available;
    size_t len;
    size_t in_use;
    size_t chunks;
};

extern struct buffer_dispatcher_storage_s global_bd_storage;

void initGBD();
shift_buffer_t* popShiftBuffer();
void reuseShiftBuffer(shift_buffer_t* b);

