#pragma once

#include "tunnel.h"
#include "wlibc.h"


/*
    a queue for context type, this helps storing it and
    later using it, its a very simple queue
*/

typedef struct context_queue_s context_queue_t;

context_queue_t *contextqueueCreate(void);
void             contextqueueDestory(context_queue_t *self);
void             contextqueuePush(context_queue_t *self, context_t *context);
context_t       *contextqueuePop(context_queue_t *self);
size_t           contextqueueLen(context_queue_t *self);
