#pragma once

#include "tunnel.h"

typedef struct context_buffer_s context_buffer_t;

context_buffer_t *newContextBuffer();
void destroyContextBuffer(context_buffer_t *self);

void contextBufferPush(context_buffer_t *self, context_t *context);
context_t * contextBufferPop(context_buffer_t *self);
size_t contextBufferLen(context_buffer_t *self);
