#pragma once

#include "tunnel.h"

typedef struct context_queue_s context_queue_t;

context_queue_t *newContextQueue();
void destroyContextQueue(context_queue_t *self);

void contextQueuePush(context_queue_t *self, context_t *context);
context_t * contextQueuePop(context_queue_t *self);
size_t contextQueueLen(context_queue_t *self);
