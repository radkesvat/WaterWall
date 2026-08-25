#pragma once

/*
 * Defines event contexts that carry line references and optional payloads
 * through tunnel callbacks.
 */

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
    uint8_t init : 1;
    uint8_t est : 1;
    uint8_t fin : 1;
    uint8_t pause : 1;
    uint8_t resume : 1;
} context_t;

/**
 * @brief Return the line currently referenced by a context.
 *
 * @param c Context instance.
 * @return line_t* Bound line.
 */
static inline line_t *contextGetLine(const context_t *const c)
{
    return c->line;
}

/**
 * @brief Create a context bound to a line and acquire a reference to that line.
 *
 * @param line Target line.
 * @return context_t* Newly allocated context from the worker pool.
 */
static inline context_t *contextCreate(line_t *const line)
{
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(lineGetWID(line)));
    *new_ctx           = (context_t){.line = line};
    lineRef(line);
    return new_ctx;
}

/**
 * @brief Clone a context's line binding into a new context.
 *
 * @param source Source context.
 * @return context_t* New context bound to the same line.
 */
static inline context_t *contextCreateFrom(const context_t *const source)
{
    lineRef(source->line);
    context_t *new_ctx = genericpoolGetItem(getWorkerContextPool(lineGetWID(contextGetLine(source))));
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

/**
 * @brief Create an establish-event context.
 *
 * @param line Target line.
 * @return context_t* Context with `est` flag set.
 */
static inline context_t *contextCreateEst(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->est       = true;
    return c;
}

/**
 * @brief Create a finish-event context.
 *
 * @param l Target line.
 * @return context_t* Context with `fin` flag set.
 */
static inline context_t *contextCreateFin(line_t *const l)
{
    context_t *c = contextCreate(l);
    c->fin       = true;
    return c;
}

/**
 * @brief Create a finish-event context from an existing context.
 *
 * @param source Source context.
 * @return context_t* Context with `fin` flag set.
 */
static inline context_t *contextCreateFinFrom(context_t *const source)
{
    context_t *c = contextCreateFrom(source);
    c->fin       = true;
    return c;
}

/**
 * @brief Create an init-event context.
 *
 * @param line Target line.
 * @return context_t* Context with `init` flag set.
 */
static inline context_t *contextCreateInit(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->init      = true;
    return c;
}

/**
 * @brief Create a payload-event context.
 *
 * @param line Target line.
 * @param payload Payload buffer ownership transferred to context.
 * @return context_t* Context carrying payload.
 */
static inline context_t *contextCreatePayload(line_t *const line,
                                              sbuf_t *const payload)
{
    context_t *c = contextCreate(line);
    c->payload   = payload;
    return c;
}

/**
 * @brief Create a pause-event context.
 *
 * @param line Target line.
 * @return context_t* Context with `pause` flag set.
 */
static inline context_t *contextCreatePause(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->pause     = true;
    return c;
}

/**
 * @brief Create a resume-event context.
 *
 * @param line Target line.
 * @return context_t* Context with `resume` flag set.
 */
static inline context_t *contextCreateResume(line_t *const line)
{
    context_t *c = contextCreate(line);
    c->resume    = true;
    return c;
}

/**
 * @brief Move a context to another line, updating line references safely.
 *
 * @param c Context to update.
 * @param line New target line.
 * @return context_t* The same context for chaining.
 */
static inline context_t *contextSwitchLine(context_t *const c, line_t *const line)
{
    lineRef(line);
    lineUnref(c->line);
    c->line = line;
    return c;
}

/*
    same as c->payload = NULL, this is necessary before destroying a context to prevent bugs, dose nothing on release
    build
*/

static inline void contextDropPayload(context_t *const c)
{
#if defined(NDEBUG)
    discard(c);
#else
    assert(c->payload != NULL);
    c->payload = NULL;
#endif
}

/**
 * @brief Return context payload to the owning worker buffer pool.
 *
 * @param c Context that owns a payload.
 */
static inline void contextReusePayload(context_t *const c)
{
    assert(c->payload != NULL);
    bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(contextGetLine(c))), c->payload);
    contextDropPayload(c);
}

/**
 * @brief Push context payload into a buffer stream and clear payload pointer.
 *
 * @param self Destination buffer stream.
 * @param c Context that owns the payload.
 */
static inline void bufferStreamPushContextPayload(buffer_stream_t *self, context_t *c)
{
    assert(c->payload);
    bufferstreamPush(self, c->payload);
    contextDropPayload(c);
}

/**
 * @brief Destroy a context, releasing payload and releasing the bound line reference.
 *
 * @param c Context to destroy.
 */
static inline void contextDestroy(context_t *c)
{
    if (c->payload)
    {
        contextReusePayload(c);
    }
    wid_t wid = lineGetWID(contextGetLine(c));
    lineUnref(c->line);
    genericpoolReuseItem(getWorkerContextPool(wid), c);
}

/**
 * @brief Apply a context event to an upstream routine on a tunnel.
 *
 * @param c Context carrying event flags or payload.
 * @param t Target tunnel.
 */
void contextApplyOnTunnelU(context_t *c, tunnel_t *t);

/**
 * @brief Apply a context event to a downstream routine on a tunnel.
 *
 * @param c Context carrying event flags or payload.
 * @param t Target tunnel.
 */
void contextApplyOnTunnelD(context_t *c, tunnel_t *t);

/**
 * @brief Apply context to the next upstream tunnel.
 *
 * @param c Context carrying event flags or payload.
 * @param t Current tunnel.
 */
static inline void contextApplyOnNextTunnelU(context_t *c, tunnel_t *t)
{
    contextApplyOnTunnelU(c, t->next);
}

/**
 * @brief Apply context to the previous downstream tunnel.
 *
 * @param c Context carrying event flags or payload.
 * @param t Current tunnel.
 */
static inline void contextApplyOnPrevTunnelD(context_t *c, tunnel_t *t)
{
    contextApplyOnTunnelD(c, t->prev);
}
