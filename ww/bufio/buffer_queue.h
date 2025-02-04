#pragma once

#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

/*
    a queue for context type, this helps storing it and
    later using it, its a very simple queue
*/

typedef struct buffer_queue_s buffer_queue_t;

buffer_queue_t *bufferqueueCreate(wid_t wid);
void            bufferqueueDestory(buffer_queue_t *self);
void            bufferqueuePush(buffer_queue_t *self, sbuf_t *b);
sbuf_t         *bufferqueuePop(buffer_queue_t *self);
size_t          bufferqueueLen(buffer_queue_t *self);
