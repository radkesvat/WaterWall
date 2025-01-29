#pragma once
#include "wlibc.h"
#include "shiftbuffer.h"
#include "generic_pool.h"
#include "global_state.h"
#include "line.h"
#include "buffer_stream.h"


/*
    Context carries information, it belongs to the line it refrenses and prevent line destruction
    untill it gets destroyed

    and it can contain a payload buffer, or be just a flag context

*/

typedef struct context_s
{
    sbuf_t *payload;
    line_t         *line;
    bool            init;
    bool            est;
    bool            fin;
} context_t;









// pool handles, instead of malloc / free  for the generic pool
pool_item_t *allocContextPoolHandle(generic_pool_t *pool);
void         destroyContextPoolHandle(generic_pool_t *pool, pool_item_t *item);

static inline void destroyContext(context_t *c)
{
    assert(c->payload == NULL);
    const tid_t tid = c->line->tid;
    lineUnlock(c->line);
    genericpoolReuseItem(getWorkerContextPool(tid), c);
}

static inline context_t *newContext(line_t *const line)
{
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(line->tid));
    *new_ctx           = (context_t){.line = line};
    lineLock(line);
    return new_ctx;
}

static inline context_t *newContextFrom(const context_t *const source)
{
    lineLock(source->line);
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(source->line->tid));
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

static inline context_t *newEstContext(line_t *const line)
{
    context_t *c = newContext(line);
    c->est       = true;
    return c;
}

static inline context_t *newFinContext(line_t *const l)
{
    context_t *c = newContext(l);
    c->fin       = true;
    return c;
}

static inline context_t *newFinContextFrom(context_t *const source)
{
    context_t *c = newContextFrom(source);
    c->fin       = true;
    return c;
}

static inline context_t *newInitContext(line_t *const line)
{
    context_t *c = newContext(line);
    c->init      = true;
    return c;
}

static inline context_t *switchLine(context_t *const c, line_t *const line)
{
    lineLock(line);
    lineUnlock(c->line);
    c->line = line;
    return c;
}

/*
    same as c->payload = NULL, this is necessary before destroying a context to prevent bugs, dose nothing on release
    build
*/

static inline void dropContexPayload(context_t *const c)
{
#if defined(RELEASE)
    (void) (c);
#else
    assert(c->payload != NULL);
    c->payload = NULL;
#endif
}

static inline void reuseContextPayload(context_t *const c)
{
    assert(c->payload != NULL);
    bufferpoolResuesBuffer(getContextBufferPool(c), c->payload);
    dropContexPayload(c);
}


static inline void bufferStreamPushContextPayload(buffer_stream_t *self, context_t *c)
{
    assert(c->payload);
    bufferstreamPush(self, c->payload);
    dropContexPayload(c);
}



static inline buffer_pool_t *getContextBufferPool(const context_t *const c)
{
    return getWorkerBufferPool(c->line->tid);
}






