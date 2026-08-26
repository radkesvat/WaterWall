#pragma once

/*
 * Defines the connection line object and helpers for line lifetime, state,
 * routing metadata, and worker-thread task scheduling.
 */

#include "wlibc.h"

#include "address_context.h"
#include "generic_pool.h"
#include "global_state.h"
#include "objects/user_handle.h"
#include "tunnel.h"
#include "worker.h"

typedef atomic_uint line_refc_t;
#define LINE_REFC_MAX 0xFFFFFFFFU

enum
{
    kLineMaxUsers = 4
};

typedef struct line_user_credentials_s
{
    char *username;
    char *password;
} line_user_credentials_t;

typedef struct line_user_auth_s
{
    bool                    has_handle;
    bool                    has_credentials;
    user_handle_t           handle;
    line_user_credentials_t credentials;
} line_user_auth_t;

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    if for example a write on the Down-end blocks, it pauses the Up-end and vice versa

    each context creation will increase refc on the line, so the line will never gets destroyed
    before the contexts that reference it. Every decrement is an acquire-release operation, so
    the final releaser acquires that release sequence before reading or reclaiming line state. This
    reference-count edge is what publishes owner teardown to a foreign final releaser.

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in tunnels_line_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily
*/

typedef struct routing_context_s
{
    address_context_t src_ctx;
    address_context_t dest_ctx;
    uint16_t          local_listener_port;
    uint16_t          peer_source_port;

} routing_context_t;

/*
 * line_t is part of the external-node ABI. External node libraries receive it
 * through flow callbacks and use the inline accessors in this header. Reordering
 * or inserting members requires an explicit ABI decision and compatibility
 * plan.
 */
typedef struct line_s
{
    line_refc_t       refc;
    bool              alive;
    wid_t             wid;
    line_user_auth_t  user_auths[kLineMaxUsers];
    uint8_t           user_count;
    uint8_t           established : 1;
    uint8_t           recalculate_checksum : 1; // used for packet tunnels
    routing_context_t routing_context;

    generic_pool_t **pools;

    MSVC_ATTR_ALIGNED_LINE_CACHE uintptr_t *tunnels_line_state[] GNU_ATTR_ALIGNED_LINE_CACHE;

} line_t;

/**
 * @brief Clears all authenticated user markers on the line.
 *
 * This releases line-owned raw credential strings and resets user_count.
 */
void lineClearUsers(line_t *const line);

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
                   .user_auths           = {0},
                   .user_count           = 0,
                   .wid                  = wid,
                   .alive                = true,
                   .pools                = pools,
                   .established          = false,
                   .recalculate_checksum = false,
                   // to set a port we need to know the AF family, default v4
                   .routing_context =
                       (routing_context_t) {.dest_ctx = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .src_ctx  = (address_context_t) {.ip_address.type = IPADDR_TYPE_V4},
                                            .local_listener_port = 0}};

    memoryZero((void *) &l->tunnels_line_state[0], genericpoolGetItemSize(pools[current]) - sizeof(line_t));

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
    assert(currentThreadIsEventWorkerWID(wid));

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
 * @brief Release one reference and free the line if the count reaches zero.
 *
 * The decrement publishes all preceding writes to the line. Its acquire
 * semantics let the final releaser observe the release sequence before it inspects
 * logical-death state, tunnel storage, routing metadata, or credentials.
 *
 * @param l Pointer to the line.
 */
void lineUnRefInternal(line_t *l);

/**
 * @brief Acquire one physical line reference.
 *
 * A line reference keeps the underlying allocation memory present, but does
 * not lock line contents, grant cross-thread access, or keep the line logically
 * alive across callbacks.
 *
 * @param line Pointer to the line.
 */
static inline void lineRef(line_t *const line)
{
    assert(line->alive);
    assert(line->refc < LINE_REFC_MAX);

    if (UNLIKELY(! line->alive) || UNLIKELY(0 == atomicIncRelaxed(&line->refc)))
    {
        printError("lineRef: attempted to reference a dead line or line reference count overflow");
        abortProgramNow(1);
    }
}

/**
 * @brief Release one physical line reference.
 *
 * A final release reclaims the allocation only after lineDestroy() has marked
 * the line logically dead. Releasing a live line to zero is a fatal contract
 * violation.
 *
 * @param line Pointer to the line.
 */
static inline void lineUnref(line_t *const line)
{
    lineUnRefInternal(line);
}

/**
 * @brief Mark the line logically dead and release its creator reference.
 *
 * @param l Pointer to the line.
 */
static inline void lineDestroy(line_t *const l)
{
    assert(l->alive);
    if (UNLIKELY(! l->alive))
    {
        printError("lineDestroy: duplicate line destruction or line is not alive");
        abortProgramNow(1);
    }
    l->alive = false;
    lineUnref(l);
}

/**
 * @brief Adds authenticated user marker(s) to the line.
 *
 * Empty or NULL user handles add an anonymous empty handle.
 * Valid user handles are copied into the line. When username/password are also
 * supplied, they are stored on the same auth marker so consumers such as Router
 * can match raw authenticated credentials without a users-table lookup.
 *
 * @param line Pointer to the line.
 * @param user_handle Optional user handle.
 * @param username Optional raw username; duplicated and stored when non-NULL.
 * @param password Optional raw password; duplicated and stored when non-NULL.
 */
void lineAddUser(line_t *const line, const user_handle_t *user_handle, const char *username, const char *password);

/**
 * @brief Add raw authenticated credentials to the line.
 *
 * This is for protocols that authenticated a peer but do not have a
 * user_handle_t from AuthenticationClient. The credentials are stored as a new
 * marker, preserving earlier authentication layers on the same line.
 *
 * @param line Pointer to the line.
 * @param username Optional raw/resolved username; duplicated when non-NULL.
 * @param password Optional raw/resolved password; duplicated when non-NULL.
 */
void lineAddAuthenticatedCredentials(line_t *const line, const char *username, const char *password);

/**
 * @brief Compatibility alias for lineAddAuthenticatedCredentials().
 */
void lineSetAuthenticatedCredentials(line_t *const line, const char *username, const char *password);

/**
 * @brief Copies all user markers from one line to a newly created companion line.
 *
 * The destination line must not already have user markers or credentials.
 *
 * @param dest Destination line.
 * @param src Source line.
 */
void lineCopyUsers(line_t *const dest, const line_t *const src);

/**
 * @brief Returns the latest user handle marker added to the line.
 *
 * @param line Pointer to the line.
 * @return const user_handle_t* Latest stored user handle marker, or NULL if no handle marker was added.
 */
const user_handle_t *lineGetCurrentUser(const line_t *const line);

/**
 * @brief Checks if the line is authenticated.
 *
 * @param line Pointer to the line.
 * @return true If the line is authenticated.
 * @return false If the line is not authenticated.
 */
static inline bool lineIsAuthenticated(line_t *const line)
{
    return line->user_count > 0;
}

/**
 * @brief Get the raw username of the latest credential marker on the line.
 *
 * @param line Pointer to the line.
 * @return const char* Username, or NULL if unknown / not authenticated by raw credentials.
 */
const char *lineGetAuthenticatedUsername(const line_t *const line);

/**
 * @brief Get the raw password of the latest credential marker on the line.
 *
 * @param line Pointer to the line.
 * @return const char* Password, or NULL if unknown / not authenticated by raw credentials.
 */
const char *lineGetAuthenticatedPassword(const line_t *const line);

/**
 * @brief Checks for an exact username match in any authenticated credential marker.
 */
bool lineHasAuthenticatedUsername(const line_t *const line, const char *username);

/**
 * @brief Checks for an exact password match in any authenticated credential marker.
 */
bool lineHasAuthenticatedPassword(const line_t *const line, const char *password);

/**
 * @brief Checks for an exact username/password pair in one authenticated credential marker.
 *
 * username or password may be NULL to act as a wildcard, but at least one should
 * be non-NULL for a meaningful match.
 */
bool lineHasAuthenticatedCredentials(const line_t *const line, const char *username, const char *password);

/**
 * @brief Get the number of authenticated user markers on the line.
 */
static inline uint8_t lineGetUserAuthCount(const line_t *const line)
{
    return line->user_count;
}

/**
 * @brief Get one authenticated user marker by index.
 */
static inline const line_user_auth_t *lineGetUserAuthAt(const line_t *const line, uint8_t index)
{
    assert(index < line->user_count);
    return &line->user_auths[index];
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
    memoryZero(state, size);
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
 * @brief Whether the calling thread is the event worker that owns this line.
 *
 * This is the affinity question to ask before touching line-owned state: it is
 * true only when the caller is a registered ordinary event worker *and* its WID
 * equals the line owner. An unregistered thread and the lwIP pseudo-worker can
 * never pass it, which a raw `lineGetWID(line) == getWID()` comparison cannot
 * guarantee.
 *
 * @param line Line instance.
 * @return true The caller owns the line and may touch its worker-local state.
 * @return false The caller must post to lineGetWID(line) instead.
 */
static inline bool lineIsOnCurrentEventWorker(const line_t *const line)
{
    return currentThreadIsEventWorkerWID(lineGetWID(line));
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

/** Terminal reason delivered when an admitted or rejected line task will not execute. */
typedef enum line_task_cancel_reason_e
{
    /** Target WID does not own an ordinary event-worker queue. */
    kLineTaskCancelTargetUnavailable = 0,
    /** Target worker no longer admits normal work or timer setup. */
    kLineTaskCancelAdmissionClosed,
    /** Queue growth or wake publication refused the submission. */
    kLineTaskCancelEnqueueFailure,
    /** Owner-side delayed resource installation failed after/before admission. */
    kLineTaskCancelResourceFailure,
    /** Worker quiescence settled accepted work before execution. */
    kLineTaskCancelQuiesced,
    /** Detached queue teardown settled the task before execution. */
    kLineTaskCancelTeardown,
    /** The physical line remained present but was logically dead at dispatch. */
    kLineTaskCancelLineDead
} line_task_cancel_reason_e;

/** What the scheduler has proved when a line-task submission function returns. */
typedef enum line_task_submit_result_e
{
    /** Refused; cancellation notification and all scheduler-owned settlement have completed. */
    kLineTaskSubmitRejectedSettled = 0,
    /** Ownership entered an asynchronous queue/setup path; later execution is not guaranteed. */
    kLineTaskSubmitAcceptedAsync,
    /** A non-zero-delay timer was installed synchronously on the line owner worker. */
    kLineTaskSubmitTimerArmed
} line_task_submit_result_e;

/**
 * @brief Notify a caller that its line task will not execute.
 *
 * Cancellation may be synchronous and re-entrant before the scheduling call
 * returns, or later on the owner worker, submitting thread, or a teardown
 * thread. The scheduler keeps its physical line reference during this call,
 * but @p l may be logically dead and its tunnel line state may already be
 * destroyed. The callback must not assume worker affinity or touch owner-only
 * state without an independent context proof. Quiescence and teardown are
 * terminal ownership settlement and must not restart normal work.
 *
 * @param t Tunnel supplied to the scheduling call.
 * @param l Physically retained target line, which may be logically dead.
 * @param reason Terminal settlement reason which won the cancellation path.
 */
typedef void (*LineTaskCancelFn)(tunnel_t *t, line_t *l, line_task_cancel_reason_e reason);

typedef void (*LineDnsResolveFn)(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                                 const dns_resolved_addr_t *addrs, size_t naddrs);

/**
 * @brief Schedule a no-buffer task on the line's next event-loop iteration.
 *
 * Submission is allowed from any thread only while the caller holds an
 * independently synchronized live handle which prevents logical destruction
 * and final reclamation until this function acquires its own reference. A raw
 * pointer, or a physical reference without a logical-life gate, is not enough
 * to race lineDestroy(). The task always executes on the immutable owner WID
 * and is force-queued rather than called inline.
 *
 * With non-NULL @p on_cancel, exactly one of @p task or @p on_cancel executes.
 * Cancellation may run synchronously before return. A NULL callback deliberately
 * declines notification; internal line/message settlement is still mandatory.
 * The pooled scheduling-record allocator is an invariant/fail-fast facility;
 * recoverable submission failures are reported through the result and callback.
 * The scheduler does not retain @p t independently: runtime/component lifetime
 * must keep that tunnel valid until task-or-cancellation settlement completes.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param t Tunnel argument forwarded to callback.
 * @param on_cancel Optional typed cancellation/settlement callback.
 * @return kLineTaskSubmitAcceptedAsync on admission, or
 *         kLineTaskSubmitRejectedSettled after synchronous cancellation and
 *         scheduler-owned settlement. Immediate submission never reports
 *         kLineTaskSubmitTimerArmed.
 */
WW_MUST_USE line_task_submit_result_e lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                       LineTaskCancelFn on_cancel);

/**
 * @brief Schedule a task with a payload buffer on the line's worker loop.
 *
 * This has the same stable-handle, owner-worker execution, result, cancellation,
 * and exactly-once contract as lineScheduleTask(). Calling transfers @p buf to
 * the scheduler even on synchronous rejection. The task owns it only when the
 * task callback executes. Otherwise the scheduler recycles it only on the owner
 * worker and destroys it on a foreign cleanup thread. Cancellation is
 * notification only and never owns or settles the buffer; it runs while the
 * physical line reference is held and before internal buffer settlement.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param t Tunnel argument forwarded to callback.
 * @param buf Buffer whose ownership always transfers to the scheduler.
 * @param on_cancel Optional typed cancellation/settlement callback.
 * @return kLineTaskSubmitAcceptedAsync on admission, or
 *         kLineTaskSubmitRejectedSettled after notification and all internal
 *         settlement. This function never reports kLineTaskSubmitTimerArmed.
 */
WW_MUST_USE line_task_submit_result_e lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t,
                                                              sbuf_t *buf, LineTaskCancelFn on_cancel);

/**
 * @brief Schedule a delayed no-buffer task on the line's worker thread.
 *
 * The stable-handle and exactly-one task-or-cancellation rules from
 * lineScheduleTask() apply. delay_ms == 0 is force-queued for a later loop
 * iteration and returns kLineTaskSubmitAcceptedAsync. A positive delay called
 * on the owner worker returns kLineTaskSubmitTimerArmed only after timer
 * installation succeeds. A foreign positive-delay submission returns
 * kLineTaskSubmitAcceptedAsync once owner-side setup is queued; timer allocation
 * may then fail asynchronously with kLineTaskCancelResourceFailure. Timer
 * failure never invokes the task inline. Quiescence/teardown cancels pending
 * work rather than rearming it.
 *
 * Delayed tasks are independent timer submissions; ordering is not guaranteed
 * between multiple delayed tasks, even when they use the same delay. If ordered
 * delivery matters, schedule one drain task and keep the ordered items in a
 * buffer_queue_t or another explicit FIFO owned by the tunnel line state.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param delay_ms Minimum delay before execution.
 * @param t Tunnel argument forwarded to callback.
 * @param on_cancel Optional typed cancellation/settlement callback.
 * @return One of all three line_task_submit_result_e states according to the
 *         synchronous proof described above. AcceptedAsync does not prove that
 *         a timer was armed or that work remains pending when observed.
 */
WW_MUST_USE line_task_submit_result_e lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task,
                                                              uint32_t delay_ms, tunnel_t *t,
                                                              LineTaskCancelFn on_cancel);

/**
 * @brief Schedule a delayed task with a buffer on the line's worker thread.
 *
 * This combines lineScheduleDelayedTask()'s immediate/zero/owner/foreign result
 * rules with lineScheduleTaskWithBuf()'s unconditional buffer transfer and
 * cancellation-before-internal-settlement ordering. A positive-delay timer
 * allocation failure is reported as kLineTaskCancelResourceFailure and never
 * by running @p task early. A NULL cancellation callback suppresses only caller
 * notification, not buffer, line-reference, or record settlement.
 *
 * Delayed tasks are independent timer submissions; ordering is not guaranteed
 * between multiple delayed tasks, even when they use the same delay. If ordered
 * delivery matters, schedule one drain task and keep the ordered items in a
 * buffer_queue_t or another explicit FIFO owned by the tunnel line state.
 *
 * @param line Target line.
 * @param task Task callback.
 * @param delay_ms Minimum delay before execution.
 * @param t Tunnel argument forwarded to callback.
 * @param buf Buffer whose ownership always transfers to the scheduler.
 * @param on_cancel Optional typed cancellation/settlement callback.
 * @return RejectedSettled, AcceptedAsync, or TimerArmed under the same proof
 *         rules as the no-buffer delayed form.
 */
WW_MUST_USE line_task_submit_result_e lineScheduleDelayedTaskWithBuf(line_t *const line, LineTaskFnWithBuf task,
                                                                     uint32_t delay_ms, tunnel_t *t, sbuf_t *buf,
                                                                     LineTaskCancelFn on_cancel);

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
 * @brief Acquire, hold, and release a temporary line reference around a task.
 *
 * The helper releases its temporary reference before returning. If it returns
 * false, the callback destroyed the line and callers must touch neither the
 * line nor its destroyed line state.
 *
 * @param line Target line.
 * @param task Callback to execute.
 * @param t Tunnel argument.
 * @return true Line remains alive after callback.
 * @return false Line was destroyed during callback.
 */
static inline bool lineCallWithRef(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t)
{
    lineRef(line);
    task(t, line);

    if (! lineIsAlive(line))
    {
        lineUnref(line);
        return false;
    }
    lineUnref(line);
    return true;
}

/**
 * @brief Acquire, hold, and release a temporary line reference around a task.
 *
 * The helper releases its temporary reference before returning. If it returns
 * false, the callback destroyed the line and callers must touch neither the
 * line nor its destroyed line state.
 *
 * @param line Target line.
 * @param task Callback to execute.
 * @param t Tunnel argument.
 * @param buf Buffer argument.
 * @return true Line remains alive after callback.
 * @return false Line was destroyed during callback.
 */
static inline bool lineCallWithRefWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf)
{
    lineRef(line);
    task(t, line, buf);

    if (! lineIsAlive(line))
    {
        lineUnref(line);
        return false;
    }
    lineUnref(line);
    return true;
}
