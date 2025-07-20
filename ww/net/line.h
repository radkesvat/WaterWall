#pragma once
#include "wlibc.h"

#include "address_context.h"
#include "generic_pool.h"
#include "global_state.h"
#include "tunnel.h"
#include "worker.h"

typedef atomic_uint line_refc_t;

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    if forexample a write on the Down-end blocks, it pauses the Up-end and vice versa

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
    const char       *user_name;
    uint8_t           user_name_len;

} routing_context_t;

typedef struct line_s
{
    line_refc_t refc;
    bool        alive;
    wid_t       wid;
    uint8_t     auth_cur;
    uint8_t     established : 1;
    uint8_t     recalculate_checksum : 1; // used for packet tunnels, ip layer checksum
    uint8_t     do_not_recalculate_transport_checksum : 1; // used for packet tunnels, skip transport layer checksum (rare used)

    routing_context_t routing_context;

    generic_pool_t *pool;

    MSVC_ATTR_ALIGNED_16 uintptr_t *tunnels_line_state[] GNU_ATTR_ALIGNED_16; 

} line_t;

/**
 * @brief Creates a new line instance.
 *
 * @param pool Pointer to the generic pool.
 * @return line_t* Pointer to the created line.
 */
static inline line_t *lineCreate(generic_pool_t *pool, wid_t wid)
{
    line_t *l = genericpoolGetItem(pool);

    *l = (line_t) {.refc                 = 1,
                   .auth_cur             = 0,
                   .wid                  = wid,
                   .alive                = true,
                   .pool                 = pool,
                   .established          = false,
                   .recalculate_checksum = false,
                   // to set a port we need to know the AF family, default v4
                   .routing_context =
                       (routing_context_t) {.network_type  = WIO_TYPE_UNKNOWN,
                                            .dest_ctx      = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .src_ctx       = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .user_name     = NULL,
                                            .user_name_len = 0

                       }};

    memorySet(&l->tunnels_line_state[0], 0, genericpoolGetItemSize(l->pool) - sizeof(line_t));

    return l;
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

    // there should not be any conn-state alive at this point

    debugAssertZeroBuf(&l->tunnels_line_state[0], genericpoolGetItemSize(l->pool) - sizeof(line_t));

    // assert(l->up_state == NULL);
    // assert(l->dw_state == NULL);

    // assert(l->src_ctx.domain == NULL); // impossible (source domain?) (no need to assert)

    if (l->routing_context.dest_ctx.domain != NULL && ! l->routing_context.dest_ctx.domain_constant)
    {
        memoryFree(l->routing_context.dest_ctx.domain);
    }

    genericpoolReuseItem(l->pool, l);
}

/**
 * @brief Increases the reference count of the line.
 *
 * @param line Pointer to the line.
 */
static inline void lineLock(line_t *const line)
{
    assert(line->alive);
    // basic overflow protection
    assert(line->refc < (((0x1ULL << ((sizeof(line->refc) * 8ULL) - 1ULL)) - 1ULL) |
                         (0xFULL << ((sizeof(line->refc) * 8ULL) - 4ULL))));
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

static inline wid_t lineGetWID(const line_t *const line)
{
    return line->wid;
}

static inline buffer_pool_t *lineGetBufferPool(const line_t *const line)
{
    return getWorkerBufferPool(lineGetWID(line));
}

static inline void lineMarkEstablished(line_t *const line)
{
    assert(! line->established);
    line->established = true;
}
static inline bool lineIsEstablished(const line_t *const line)
{
    return line->established;
}

static inline void lineSetRecalculateChecksum(line_t *const line, bool recalculate)
{
    line->recalculate_checksum = recalculate;
}
static inline bool lineGetRecalculateChecksum(const line_t *const line)
{
    return line->recalculate_checksum;
}

static inline routing_context_t *lineGetRoutingContext(line_t *const line)
{
    return &line->routing_context;
}

static inline address_context_t *lineGetSourceAddressContext(line_t *const line)
{
    return &line->routing_context.src_ctx;
}

static inline address_context_t *lineGetDestinationAddressContext(line_t *const line)
{
    return &line->routing_context.dest_ctx;
}
