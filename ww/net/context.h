#pragma once
#include "buffer_stream.h"
#include "generic_pool.h"
#include "global_state.h"
#include "line.h"
#include "shiftbuffer.h"
#include "wlibc.h"

/*
    Context carries information, it belongs to the line it refrenses and prevent line destruction
    untill it gets destroyed

    and it can contain a payload buffer, or be just a flag context

*/

typedef struct context_s
{
    sbuf_t *payload;
    line_t *line;
    bool    init;
    bool    est;
    bool    fin;
} context_t;

static inline void contextDestroy(context_t *c)
{
    assert(c->payload == NULL);
    const tid_t tid = c->line->tid;
    lineUnlock(c->line);
    genericpoolReuseItem(getWorkerContextPool(tid), c);
}

static inline context_t *contextCreate(line_t *const line)
{
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(line->tid));
    *new_ctx           = (context_t){.line = line};
    lineLock(line);
    return new_ctx;
}

static inline context_t *contextCreateFrom(const context_t *const source)
{
    lineLock(source->line);
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(source->line->tid));
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

static inline context_t *contextCreateEst(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->est       = true;
    return c;
}

static inline context_t *contextCreateFin(line_t *const l)
{
    context_t *c = contextCreate(l);
    c->fin       = true;
    return c;
}

static inline context_t *contextCreateFinFrom(context_t *const source)
{
    context_t *c = contextCreateFrom(source);
    c->fin       = true;
    return c;
}

static inline context_t *contextCreateInit(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->init      = true;
    return c;
}

static inline context_t *contextSwitchLine(context_t *const c, line_t *const line)
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

static inline void contextDropPayload(context_t *const c)
{
#if defined(RELEASE)
    (void) (c);
#else
    assert(c->payload != NULL);
    c->payload = NULL;
#endif
}

static inline buffer_pool_t *contextGetBufferPool(const context_t *const c)
{
    return getWorkerBufferPool(c->line->tid);
}

static inline void contextReusePayload(context_t *const c)
{
    assert(c->payload != NULL);
    bufferpoolResuesBuffer(contextGetBufferPool(c), c->payload);
    contextDropPayload(c);
}

static inline void bufferStreamPushContextPayload(buffer_stream_t *self, context_t *c)
{
    assert(c->payload);
    bufferstreamPush(self, c->payload);
    contextDropPayload(c);
}
