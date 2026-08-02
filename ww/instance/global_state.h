#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "generic_pool.h"
#include "net/address_context.h"
#include "threadsafe_generic_pool.h"
#include "wloop.h"
#include "worker.h"
#include "worker_messages.h"
#include "wsysinfo.h"

/*
    This is a global state file that powers many WW things up

    this also dose not limit loading another WW lib dynamically, it manages
    the loaded library and sets it up so there is no such problem of multiple global symbols

*/

typedef struct
{
    char *log_file_path;
    char *log_level;
    bool  log_console;

} logger_construction_data_t;

typedef err_t (*LwipV4Hook)(struct pbuf *, struct netif *);

#if defined(OS_WIN)
typedef LONG(WINAPI *secure_random_windows_generator_fn)(void *, unsigned char *, ULONG, ULONG);
#endif

typedef struct secure_random_state_s
{
#if defined(OS_WIN)
    HMODULE                            library_handle;
    secure_random_windows_generator_fn generator;
#elif defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
    int device_fd;
#endif
    bool initialized;
} secure_random_state_t;

typedef struct ww_global_state_s
{
    wloop_t                   **shortcut_loops;
    buffer_pool_t             **shortcut_buffer_pools;
    threadsafe_generic_pool_t **shortcut_wios_pools;
    generic_pool_t            **shortcut_context_pools;
    master_pool_t              *masterpool_buffer_pools_large;
    master_pool_t              *masterpool_buffer_pools_small;
    master_pool_t              *masterpool_wios;
    master_pool_t              *masterpool_context_pools;
    master_pool_t              *masterpool_messages;
    worker_t                   *workers;
    struct signal_manager_s    *signal_manager;
    struct socket_manager_s    *socekt_manager;
    struct node_manager_s      *node_manager;
    struct logger_s            *core_logger;
    struct logger_s            *network_logger;
    struct logger_s            *dns_logger;
    struct logger_s            *internal_logger;
    struct dedicated_memory_s  *openssl_dedicated_memory;
    LwipV4Hook                  lwip_process_v4_hook;
    secure_random_state_t       secure_random;
    system_load_state_t        *system_load;
    void                       *wintun_dll_handle;
    void                       *windivert_dll_handle;
    uint32_t                    workers_count;
    uint32_t                    ram_profile;
    asyncdns_options_t          dns_options;
    enum domain_strategy        domain_strategy;
    uint64_t                    main_thread_id;
    wid_t                       lwip_wid;
    atomic_wid_t                distribute_wid;
    uint16_t                    buffer_allocation_padding;
    uint16_t                    capturedevice_queue_start_number;
    uint16_t                    mtu_size;
    uint8_t                     flag_initialized : 1;
    uint8_t                     flag_buffers_calculated : 1;
    uint8_t                     flag_tundev_windows_initialized : 1;
    uint8_t                     flag_openssl_initialized : 1;
    uint8_t                     flag_libsodium_initialized : 1;
    uint8_t                     flag_lwip_initialized : 1;
    atomic_bool                 application_stopping_flag; // prevent threads sending messages to each other
    atomic_bool                 workers_run_flag;          // main thread sets this to true when it started its loop

    // Published by a TunDevice in system-route mode before worker traffic runs.
    // Outbound connector sockets use this to pin WaterWall's own egress to the
    // physical default interface and avoid routing back into the TUN.
    atomic_bool tun_egress_pin_active;
    char        tun_egress_ifname[64];
    uint32_t    tun_egress_ifindex_v4;
    uint32_t    tun_egress_ifindex_v6;
    uint32_t    tun_egress_pin_refs;

} ww_global_state_t;

typedef struct
{
    unsigned int               workers_count;
    enum ram_profiles_e        ram_profile;
    uint16_t                   mtu_size;
    asyncdns_options_t         dns_options;
    enum domain_strategy       domain_strategy;
    logger_construction_data_t internal_logger_data;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

extern ww_global_state_t global_ww_state;

#define GSTATE               global_ww_state
#define GLOBAL_MTU_SIZE      global_ww_state.mtu_size
#define RAM_PROFILE          global_ww_state.ram_profile
#define WORKERS              global_ww_state.workers
#define WORKERS_COUNT        global_ww_state.workers_count
#define WORKER_ADDITIONS     1 // 1 for lwip thread (included in workers_count)
#define MAX_ORDINARY_WORKERS (kInvalidWID - WORKER_ADDITIONS)

/*!
 * @brief Get the number of total workers.
 *        This includes additional threads that is created during startup
 *        but they may not have an event loop instance!
 *
 *        note that threads that tunnels may create are not counted as workers (eg TunDevice node)
 * @return The number of workers.
 */
static inline wid_t getTotalWorkersCount(void)
{
    return (wid_t) WORKERS_COUNT;
}

/*!
 * @brief Get the number of workers.
 *
 * @return The number of workers.
 */
static inline wid_t getWorkersCount(void)
{
    return (wid_t) WORKERS_COUNT - WORKER_ADDITIONS;
}

/*!
 * @brief Get a worker by its ID.
 *
 * @param wid The worker ID.
 * @return A pointer to the worker.
 */
static inline worker_t *getWorker(wid_t wid)
{
    assert(GSTATE.flag_initialized && WORKERS != NULL);
    assert(wid != kInvalidWID);
    assert(wid < getTotalWorkersCount());
    if (UNLIKELY(wid == kInvalidWID || wid >= getTotalWorkersCount()))
    {
        abortProgramNow(1);
    }
    return &(WORKERS[wid]);
}

/*!
 * @brief Get the buffer pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the buffer pool.
 */
static inline buffer_pool_t *getWorkerBufferPool(wid_t wid)
{
    assert(GSTATE.flag_initialized && GSTATE.shortcut_buffer_pools != NULL);
    assert(wid != kInvalidWID);
    assert(wid < getTotalWorkersCount());
    if (UNLIKELY(wid == kInvalidWID || wid >= getTotalWorkersCount()))
    {
        abortProgramNow(1);
    }
    return GSTATE.shortcut_buffer_pools[wid];
}

/*!
 * @brief Get the Wios pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the Wios pool.
 */
static inline threadsafe_generic_pool_t *getWorkerWiosPool(wid_t wid)
{
    assert(GSTATE.flag_initialized && GSTATE.shortcut_wios_pools != NULL);
    assert(wid != kInvalidWID);
    assert(wid < getTotalWorkersCount());
    if (UNLIKELY(wid == kInvalidWID || wid >= getTotalWorkersCount()))
    {
        abortProgramNow(1);
    }
    return GSTATE.shortcut_wios_pools[wid];
}

/*!
 * @brief Get the context pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the context pool.
 */
static inline generic_pool_t *getWorkerContextPool(wid_t wid)
{
    assert(GSTATE.flag_initialized && GSTATE.shortcut_context_pools != NULL);
    assert(wid != kInvalidWID);
    assert(wid < getTotalWorkersCount());
    if (UNLIKELY(wid == kInvalidWID || wid >= getTotalWorkersCount()))
    {
        abortProgramNow(1);
    }
    return GSTATE.shortcut_context_pools[wid];
}

/*!
 * @brief Get the event loop for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the event loop.
 */
static inline struct wloop_s *getWorkerLoop(wid_t wid)
{
    assert(GSTATE.flag_initialized && GSTATE.shortcut_loops != NULL);
    assert(wid != kInvalidWID);
    assert(wid < getTotalWorkersCount());
    if (UNLIKELY(wid == kInvalidWID || wid >= getTotalWorkersCount()))
    {
        abortProgramNow(1);
    }
    return GSTATE.shortcut_loops[wid];
}

/*!
 * @brief Reports a current-event-worker contract violation and aborts.
 *
 * Kept out of line so the checked accessors below stay small on hot paths. It
 * logs the accessor name, the observed WID (or "unregistered"), and the OS
 * thread id, which is what actually identifies the offending thread.
 *
 * @param accessor Name of the accessor whose contract was violated.
 */
WW_EXPORT _Noreturn void globalstateAbortNotEventWorker(const char *accessor);

/*!
 * @brief The worker owning the current thread, for event-worker-only callbacks.
 *
 * Use this in internal callbacks whose contract already guarantees an ordinary
 * event worker (event-loop/timer/wio callbacks, worker-message callbacks, tunnel
 * payload handlers). It never falls back to worker 0: an unregistered thread or
 * the lwIP pseudo-worker aborts instead.
 *
 * Externally reachable or otherwise fallible code must branch on
 * currentThreadIsEventWorker()/tryGetCurrentEventWorker() and fail cleanly
 * rather than calling this.
 *
 * @return A pointer to the current thread's worker.
 */
static inline worker_t *getCurrentEventWorker(void)
{
    const wid_t wid = getWID();
    if (UNLIKELY(! workerWIDIsEventWorker(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return &(WORKERS[wid]);
}

/*!
 * @brief Nullable form of getCurrentEventWorker(), for fallible callers.
 *
 * @return The current thread's worker, or NULL when the caller is unregistered,
 *         is the lwIP pseudo-worker, or runs before/after worker storage exists.
 */
static inline worker_t *tryGetCurrentEventWorker(void)
{
    const wid_t wid = getWID();
    if (! workerWIDIsEventWorker(wid))
    {
        return NULL;
    }
    return &(WORKERS[wid]);
}

/*!
 * @brief The current thread's own event-worker id, validated once.
 *
 * Prefer this over repeatedly reading getWID() when a callback needs its WID for
 * both a per-worker array and a worker-local resource.
 *
 * @return The current worker ID. Aborts when the caller is not an event worker.
 */
static inline wid_t getCurrentEventWorkerWID(void)
{
    const wid_t wid = getWID();
    if (UNLIKELY(! workerWIDIsEventWorker(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return wid;
}

/*!
 * @brief The buffer pool owned by the current event worker.
 *
 * Same contract as getCurrentEventWorker(): callers that may run on an
 * unregistered or lwIP thread must not use it.
 *
 * @return A pointer to the current worker's buffer pool.
 */
static inline buffer_pool_t *getCurrentEventWorkerBufferPool(void)
{
    const wid_t wid = getWID();
    if (UNLIKELY(! workerWIDIsEventWorker(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return GSTATE.shortcut_buffer_pools[wid];
}

/*!
 * @brief The context pool owned by the current event worker.
 *
 * @return A pointer to the current worker's context pool.
 */
static inline generic_pool_t *getCurrentEventWorkerContextPool(void)
{
    const wid_t wid = getWID();
    if (UNLIKELY(! workerWIDIsEventWorker(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return GSTATE.shortcut_context_pools[wid];
}

/*!
 * @brief The event loop owned by the current event worker.
 *
 * The worker role comes from `has_event_loop`, so this stays valid for a worker
 * that is tearing down and has already detached `worker->loop`. Callers running
 * during teardown must still tolerate a loop that no longer accepts work.
 *
 * @return A pointer to the current worker's event loop.
 */
static inline struct wloop_s *getCurrentEventWorkerLoop(void)
{
    const wid_t wid = getWID();
    if (UNLIKELY(! workerWIDIsEventWorker(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return GSTATE.shortcut_loops[wid];
}

/*!
 * @brief The event worker that owns @p loop, validated against the caller.
 *
 * The preferred source of identity inside a loop/io/timer callback: the event
 * being dispatched already names its owning loop, so this reads the WID from the
 * loop and only checks TLS to confirm the callback really is running on it.
 * Derive it once and reuse the result for every per-worker array and resource in
 * the callback.
 *
 * @param loop Loop the callback was dispatched from.
 * @return The owning worker ID. Aborts when the caller does not own that loop.
 */
static inline wid_t getLoopEventWorkerWID(struct wloop_s *loop)
{
    const wid_t wid = (wid_t) wloopGetWID(loop);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid)))
    {
        globalstateAbortNotEventWorker(__func__);
    }
    return wid;
}

/*!
 * @brief Cached "now" in milliseconds for a worker's event loop.
 *
 * Reads the loop's cached timestamp (refreshed once per loop iteration by
 * wloopUpdateTime), so the accessor is a cached read instead of a clock_gettime
 * syscall. Accuracy is one loop iteration, which is sufficient for ms-scale
 * timekeeping on hot data paths. Must be called from the worker that owns @p wid.
 *
 * @param wid The worker ID.
 * @return Cached wall-clock time in milliseconds.
 */
static inline uint64_t getWorkerNowMS(wid_t wid)
{
    return wloopNowMS(getWorkerLoop(wid));
}

/*!
 * @brief Cached "now" in microseconds for a worker's event loop.
 *
 * Microsecond-resolution counterpart of getWorkerNowMS(); same caching and
 * threading constraints apply.
 *
 * @param wid The worker ID.
 * @return Cached wall-clock time in microseconds.
 */
static inline uint64_t getWorkerNowUS(wid_t wid)
{
    return wloopNowUS(getWorkerLoop(wid));
}

static inline wid_t getNextDistributionWID(void)
{
    wid_t wid = atomicAddExplicit(&GSTATE.distribute_wid, 1, memory_order_relaxed);

    // we dont consider lwip thread
    if (wid >= getWorkersCount())
    {
        atomicStoreRelaxed(&GSTATE.distribute_wid, 1);
        wid = 0;
    }

    return wid;
}

/*!
 * @brief Runs the main thread.
 */
WW_EXPORT void runMainThread(void);

/*!
 * @brief Exits the main thread.
 *
 * This function exits the main thread
 */
WW_EXPORT void finishGlobalState(void);

/*!
 * @brief Creates the global state.
 *
 * @param data The construction data for the global state.
 */
WW_EXPORT void createGlobalState(ww_construction_data_t data);
/*!
 * @brief Gets the global state.
 *
 * @return A pointer to the global state.
 */
WW_EXPORT ww_global_state_t *getGlobalState(void);
/*!
 * @brief Sets the global state.
 *
 * @param state A pointer to the global state.
 */
WW_EXPORT void setGlobalState(ww_global_state_t *state);

/*
 * Initializes and probes the process-wide secure random provider.
 * createGlobalState() calls this before workers or tunnels are started.
 */
WW_EXPORT bool globalstateInitializeSecureRandom(void);

/* Releases resources cached by globalstateInitializeSecureRandom(). */
WW_EXPORT void globalstateDestroySecureRandom(void);

WW_EXPORT void globalstateStopSystemLoadSampler(void);

/*!
 * @brief Updates the allocation padding for the global state.
 *
 * @param padding The padding value.
 */
WW_EXPORT void globalstateUpdateAllocationPadding(uint16_t padding);

/*!
 * @brief Initializes the Lwip worker and spawn it.
 */
WW_EXPORT void initTcpIpStack(void);

/*!
 * @brief Destroys global state, all threads must be stopped before doing this
 */
WW_EXPORT void destroyGlobalState(void);

/**
 * Recycles a buffer into the **current event worker's** pool.
 *
 * This is only correct when the calling thread owns the buffer's pool, which is
 * why it rejects unregistered threads and the lwIP pseudo-worker instead of
 * indexing a shortcut array. Cross-worker cleanup paths must not be converted to
 * it: use lineReuseBuffer()/bufferpoolReuseBuffer() with the owning pool when the
 * owner is known, or sbufDestroy() when it is not.
 *
 * @param b The buffer to recycle.
 */
WW_EXPORT void reuseBuffer(sbuf_t *b);
