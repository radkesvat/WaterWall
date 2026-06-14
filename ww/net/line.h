#pragma once

/*
 * Defines the connection line object and helpers for line lifetime, state,
 * routing metadata, and worker-thread task scheduling.
 */

#include "wlibc.h"

#include "address_context.h"
#include "generic_pool.h"
#include "global_state.h"
#include "tunnel.h"
#include "worker.h"

typedef atomic_uint line_refc_t;
#define LINE_REFC_MAX 0xFFFFFFFFU

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    if for example a write on the Down-end blocks, it pauses the Up-end and vice versa

    each context creation will increase refc on the line, so the line will never gets destroyed
    before the contexts that reference it

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in tunnels_line_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily
*/

typedef struct routing_context_s
{
    address_context_t src_ctx;
    address_context_t dest_ctx;
    wio_type_e        network_type;
    uint16_t          local_listener_port;

} routing_context_t;

typedef struct line_s
{
    line_refc_t       refc;
    bool              alive;
    wid_t             wid;
    uint8_t           auth_cur;
    uint8_t           established : 1;
    uint8_t           recalculate_checksum : 1; // used for packet tunnels
    routing_context_t routing_context;

    generic_pool_t **pools;

    MSVC_ATTR_ALIGNED_LINE_CACHE uintptr_t *tunnels_line_state[] GNU_ATTR_ALIGNED_LINE_CACHE;

} line_t;

/**
 * @brief Allocate and initialize a line in a specific worker pool.
 *
 * @param current Worker whose pool is used for allocation.
 * @param pools Per-worker line pools.
 * @param wid Owner worker id written into the line.
 * @return line_t* Initialized line.
 */
static inline line_t *lineCreateForWorker(wid_t current, generic_pool_t **pools, wid_t wid)
{

    line_t *l = genericpoolGetItem(pools[current]);

    *l = (line_t) {.refc                 = 1,
                   .auth_cur             = 0,
                   .wid                  = wid,
                   .alive                = true,
                   .pools                = pools,
                   .established          = false,
                   .recalculate_checksum = false,
                   // to set a port we need to know the AF family, default v4
                   .routing_context =
                       (routing_context_t) {.network_type = WIO_TYPE_UNKNOWN,
                                            .dest_ctx     = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .src_ctx      = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .local_listener_port = 0}};

    memorySet((void *) &l->tunnels_line_state[0], 0, genericpoolGetItemSize(pools[current]) - sizeof(line_t));

    return l;
}

/**
 * @brief Creates a new line instance.
 *
 * @param pools Pointer to the array of generic pools. (per WID)
 * @return line_t* Pointer to the created line.
 */
static inline line_t *lineCreate(generic_pool_t **pools, wid_t wid)
{
    assert(wid == getWID());

    return lineCreateForWorker(wid, pools, wid);
}

/**
 * @brief Checks if the line is alive.
 *
 * @param line Pointer to the line.
 * @return true If the line is alive.
 * @return false If the line is not alive.
 */
static inline bool lineIsAlive(const line_t *const line)
{
    return line->alive;
}

/**
 * @brief Decreases the reference count of the line and frees it if the count reaches zero.
 *
 * @param l Pointer to the line.
 */
static inline void lineUnRefInternal(line_t *const l)
{
    if (atomicDecRelaxed(&l->refc) > 1)
    {
        return;
    }

    assert(l->alive == false);

    wid_t wid = getWID();

    // there should not be any conn-state alive at this point

    debugAssertZeroBuf(&l->tunnels_line_state[0], genericpoolGetItemSize(l->pools[wid]) - sizeof(line_t));

    if (l->routing_context.dest_ctx.domain != NULL && ! l->routing_context.dest_ctx.domain_constant)
    {
        memoryFree(l->routing_context.dest_ctx.domain);
    }
    genericpoolReuseItem(l->pools[wid], l);
}

/**
 * @brief Increases the reference count of the line.
 *
 * @param line Pointer to the line.
 */
static inline void lineLock(line_t *const line)
{
    assert(line->alive);
    assert(line->refc < LINE_REFC_MAX);

    if (0 == atomicIncRelaxed(&line->refc))
    {
        assert(false);
    }
}

/**
 * @brief Decreases the reference count of the line.
 *
 * @param line Pointer to the line.
 */
static inline void lineUnlock(line_t *const line)
{
    lineUnRefInternal(line);
}

/**
 * @brief Marks the line as destroyed and decreases its reference count.
 *
 * @param l Pointer to the line.
 */
static inline void lineDestroy(line_t *const l)
{
    assert(l->alive);
    l->alive = false;
    lineUnlock(l);
}

/**
 * @brief Authenticates the line.
 *
 * @param line Pointer to the line.
 */
static inline void lineAuthenticate(line_t *const line)
{
    // basic overflow protection
    assert(line->auth_cur < (((0x1ULL << ((sizeof(line->auth_cur) * 8ULL) - 1ULL)) - 1ULL) |
                             (0xFULL << ((sizeof(line->auth_cur) * 8ULL) - 4ULL))));
    line->auth_cur += 1;
}

/**
 * @brief Checks if the line is authenticated.
 *
 * @param line Pointer to the line.
 * @return true If the line is authenticated.
 * @return false If the line is not authenticated.
 */
static inline bool lineIsAuthenticated(line_t *const line)
{
    return line->auth_cur > 0;
}

/**
 * @brief Retrieves the state of the line for a given tunnel.
 *
 * @param l Pointer to the line.
 * @param t Pointer to the tunnel.
 * @return void* Pointer to the state of the line.
 */
static inline void *lineGetState(line_t *l, tunnel_t *t)
{
    return ((uint8_t *) l->tunnels_line_state) + t->lstate_offset;
}

/**
 * @brief Clears the state of the line.
 *
 * @param state Pointer to the state.
 * @param size Size of the state.
 */
static inline void lineClearState(void *state, size_t size)
{
#ifdef DEBUG
    memorySet(state, 0, size);
#endif
    discard size;
    discard state;
}

/**
 * @brief Get the owner worker id of a line.
 *
 * @param line Line instance.
 * @return wid_t Worker id.
 */
static inline wid_t lineGetWID(const line_t *const line)
{
    return line->wid;
}

/**
 * @brief Get the buffer pool that belongs to the line owner worker.
 *
 * @param line Line instance.
 * @return buffer_pool_t* Worker-local buffer pool.
 */
static inline buffer_pool_t *lineGetBufferPool(const line_t *const line)
{
    return getWorkerBufferPool(lineGetWID(line));
}

/**
 * @brief Reuse a buffer using the line's worker buffer pool.
 *
 * @param line Line instance.
 * @param b Buffer to return.
 */
static inline void lineReuseBuffer(const line_t *const line, sbuf_t *b)
{
    bufferpoolReuseBuffer(lineGetBufferPool(line), b);
}

/**
 * @brief Mark a line as established.
 *
 * @param line Line instance.
 */
static inline void lineMarkEstablished(line_t *const line)
{
    assert(! line->established);
    line->established = true;
}

/**
 * @brief Check whether a line is established.
 *
 * @param line Line instance.
 * @return true Line is established.
 * @return false Line is not established.
 */
static inline bool lineIsEstablished(const line_t *const line)
{
    return line->established;
}

/**
 * @brief Set the packet checksum recalculation flag on a line.
 *
 * @param line Line instance.
 * @param recalculate New flag value.
 */
static inline void lineSetRecalculateChecksum(line_t *const line, bool recalculate)
{
    line->recalculate_checksum = recalculate;
}

/**
 * @brief Get the packet checksum recalculation flag from a line.
 *
 * @param line Line instance.
 * @return true Recalculation is requested.
 * @return false Recalculation is disabled.
 */
static inline bool lineGetRecalculateChecksum(const line_t *const line)
{
    return line->recalculate_checksum;
}

/**
 * @brief Access routing metadata attached to a line.
 *
 * @param line Line instance.
 * @return routing_context_t* Routing context.
 */
static inline routing_context_t *lineGetRoutingContext(line_t *const line)
{
    return &line->routing_context;
}

/**
 * @brief Access source address context of a line.
 *
 * @param line Line instance.
 * @return address_context_t* Source address context.
 */
static inline address_context_t *lineGetSourceAddressContext(line_t *const line)
{
    return &line->routing_context.src_ctx;
}

/**
 * @brief Access destination address context of a line.
 *
 * @param line Line instance.
 * @return address_context_t* Destination address context.
 */
static inline address_context_t *lineGetDestinationAddressContext(line_t *const line)
{
    return &line->routing_context.dest_ctx;
}

typedef void (*LineTaskFnWithBuf)(tunnel_t *t, line_t *l, sbuf_t *buf);
typedef void (*LineTaskFnNoBuf)(tunnel_t *t, line_t *l);
typedef void (*LineDnsResolveFn)(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                                 const dns_resolved_addr_t *addrs, size_t naddrs);

/**
 * @brief Schedule a no-buffer task on the line's next event-loop iteration.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param t Tunnel argument forwarded to callback.
 */
void lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t);

/**
 * @brief Schedule a task with a payload buffer on the line's worker loop.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param t Tunnel argument forwarded to callback.
 * @param buf Buffer argument forwarded to callback.
 */
void lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf);

/**
 * @brief Schedule a delayed no-buffer task on the line's worker thread.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param delay_ms Minimum delay before execution.
 * @param t Tunnel argument forwarded to callback.
 */
void lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms, tunnel_t *t);

/**
 * @brief Schedule a delayed task with a buffer on the line's worker thread.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param delay_ms Minimum delay before execution.
 * @param t Tunnel argument forwarded to callback.
 * @param buf Buffer argument forwarded to callback.
 */
void lineScheduleDelayedTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, uint32_t delay_ms, tunnel_t *t,
                                    sbuf_t *buf);

/**
 * @brief Resolve a domain on the line's worker while keeping the line alive.
 *
 * Must be called from line->wid. The callback runs only if the line is still
 * alive when the DNS result arrives. Resolver cleanup statuses are consumed by
 * this helper after releasing the line reference; no user callback is invoked
 * for ARES_ECANCELLED or ARES_EDESTRUCTION.
 *
 * @param line Target line.
 * @param domain Domain name to resolve.
 * @param cb DNS result callback.
 * @param t Tunnel argument forwarded to callback.
 * @param userdata User argument forwarded to callback.
 * @return ARES_SUCCESS if the request was submitted, otherwise a c-ares error.
 */
int lineResolveDomainAsync(line_t *const line, const char *domain, LineDnsResolveFn cb, tunnel_t *t, void *userdata);

/**
 * @brief Resolve a domain/service pair on the line's worker while keeping the line alive.
 *
 * Must be called from line->wid. The callback runs only if the line is still
 * alive when the DNS result arrives. Resolver cleanup statuses are consumed by
 * this helper after releasing the line reference; no user callback is invoked
 * for ARES_ECANCELLED or ARES_EDESTRUCTION.
 *
 * @param line Target line.
 * @param domain Domain name to resolve.
 * @param service Optional service name or port string.
 * @param socktype Socket type hint, such as 0, SOCK_STREAM, or SOCK_DGRAM.
 * @param cb DNS result callback.
 * @param t Tunnel argument forwarded to callback.
 * @param userdata User argument forwarded to callback.
 * @return ARES_SUCCESS if the request was submitted, otherwise a c-ares error.
 */
int lineResolveDomainServiceAsync(line_t *const line, const char *domain, const char *service, int socktype,
                                  LineDnsResolveFn cb, tunnel_t *t, void *userdata);

/**
 * @brief Run a no-buffer task while holding a temporary line reference.
 *
 * @param line Target line.
 * @param task Callback to execute.
 * @param t Tunnel argument.
 * @return true Line remains alive after callback.
 * @return false Line was destroyed during callback.
 */
static inline bool withLineLocked(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t)
{
    lineLock(line);
    task(t, line);

    if (! lineIsAlive(line))
    {
        lineUnlock(line);
        return false;
    }
    lineUnlock(line);
    return true;
}

/**
 * @brief Run a buffered task while holding a temporary line reference.
 *
 * @param line Target line.
 * @param task Callback to execute.
 * @param t Tunnel argument.
 * @param buf Buffer argument.
 * @return true Line remains alive after callback.
 * @return false Line was destroyed during callback.
 */
static inline bool withLineLockedWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf)
{
    lineLock(line);
    task(t, line, buf);

    if (! lineIsAlive(line))
    {
        lineUnlock(line);
        return false;
    }
    lineUnlock(line);
    return true;
}
