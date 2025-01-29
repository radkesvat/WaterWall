#pragma once
#include "wlibc.h"

#include "generic_pool.h"
#include "global_state.h"
#include "socket_context.h"
#include "worker.h"

typedef uint32_t line_refc_t;

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    if forexample a write on the Down-end blocks, it pauses the Up-end and wice wersa

    each context creation will increase refc on the line, so the line will never gets destroyed
    before the contexts that refrense it

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in tunnels_line_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily

*/

typedef struct line_s
{
    line_refc_t      refc;
    tid_t            tid;
    bool             alive;
    uint8_t          auth_cur;
    
    socket_context_t src_ctx;
    socket_context_t dest_ctx;
    generic_pool_t  *pool;
    // pipe_line_t     *pipe;

    uintptr_t *tunnels_line_state[] __attribute__((aligned(sizeof(void *))));

} line_t;

static inline line_t *newLine(generic_pool_t *pool, tid_t tid)
{
    line_t *l = genericpoolGetItem(pool);

    *l = (line_t){.tid      = tid,
                  .refc     = 1,
                  .auth_cur = 0,
                  .alive    = true,
                  .pool     = pool,
                  // to set a port we need to know the AF family, default v4
                  .dest_ctx = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
                  .src_ctx = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}}};

    memorySet(&l->tunnels_line_state[0], 0, genericpoolGetItemSize(l->pool) - sizeof(line_t));

    return l;
}

static inline bool lineIsAlive(const line_t *const line)
{
    return line->alive;
}

/*
    called from unlockline which mostly is because destroy context
*/
static inline void lineUnRefInternal(line_t *const l)
{
    if (--(l->refc) > 0)
    {
        return;
    }

    assert(l->alive == false);

    // there should not be any conn-state alive at this point

    debugAssertZeroBuf(&l->tunnels_line_state[0], genericpoolGetItemSize(l->pool) - sizeof(line_t));

    // assert(l->up_state == NULL);
    // assert(l->dw_state == NULL);

    // assert(l->src_ctx.domain == NULL); // impossible (source domain?) (no need to assert)

    if (l->dest_ctx.domain != NULL && ! l->dest_ctx.domain_constant)
    {
        memoryFree(l->dest_ctx.domain);
    }

    genericpoolReuseItem(l->pool, l);
}

/*
    called mostly because create context
*/
static inline void lineLock(line_t *const line)
{
    assert(line->alive || line->refc > 0);
    // basic overflow protection
    assert(line->refc < (((0x1ULL << ((sizeof(line->refc) * 8ULL) - 1ULL)) - 1ULL) |
                         (0xFULL << ((sizeof(line->refc) * 8ULL) - 4ULL))));
    line->refc++;
}

static inline void lineUnlock(line_t *const line)
{
    lineUnRefInternal(line);
}

/*
    Only the line creator must call this when it wants to end the line, this dose not necessarily free the line
   instantly, but it will be freed as soon as the refc becomes zero which means no context is alive for this line, and
   the line can still be used regularly during the time that it has at least 1 ref

*/
static inline void lineDestroy(line_t *const l)
{
    l->alive = false;
    lineUnlock(l);
}

static inline void lineAuthenticate(line_t *const line)
{
    // basic overflow protection
    assert(line->auth_cur < (((0x1ULL << ((sizeof(line->auth_cur) * 8ULL) - 1ULL)) - 1ULL) |
                             (0xFULL << ((sizeof(line->auth_cur) * 8ULL) - 4ULL))));
    line->auth_cur += 1;
}

static inline bool lineIsAuthenticated(line_t *const line)
{
    return line->auth_cur > 0;
}

static inline buffer_pool_t *lineGetBufferPool(const line_t *const l)
{
    return getWorkerBufferPool(l->tid);
}

static inline wloop_t *lineGetEventLoop(const line_t *const l)
{
    return getWorkerLoop(l->tid);
}

// static inline bool isUpPiped(const line_t *const l)
// {
//     return l->pipe != NULL && l->pipe->up != NULL;
// }

// static inline bool isDownPiped(const line_t *const l)
// {
//     return l->pipe != NULL && l->pipe->dw != NULL;
// }
