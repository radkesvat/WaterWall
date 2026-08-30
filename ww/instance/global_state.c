#include "global_state.h"
#include "application_shutdown.h"
#include "buffer_pool.h"
#include "bufio/buffer_pool.h"
#include "bufio/master_pool.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"
#include "objects/user_handle.h"

#if defined(OS_WIN)
#include "devices/tun/tun.h"
#endif

#include <ares.h>

#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
#include <fcntl.h>
#include <unistd.h>
#endif

#include "crypto/wcrypto.h"

// Global instance of the ww_global_state_t structure.
ww_global_state_t global_ww_state = {0};

// --- Static helper functions ---

static void globalstateDestroyWorkersThatNeverStarted(wid_t first);

static void globalstateDestroyMasterPools(void)
{
    masterpoolMakeEmpty(GSTATE.masterpool_buffer_pools_large);
    masterpoolMakeEmpty(GSTATE.masterpool_buffer_pools_small);
    masterpoolMakeEmpty(GSTATE.masterpool_wios);
    masterpoolMakeEmpty(GSTATE.masterpool_context_pools);
    masterpoolMakeEmpty(GSTATE.masterpool_messages);

    masterpoolDestroy(GSTATE.masterpool_buffer_pools_large);
    masterpoolDestroy(GSTATE.masterpool_buffer_pools_small);
    masterpoolDestroy(GSTATE.masterpool_wios);
    masterpoolDestroy(GSTATE.masterpool_context_pools);
    masterpoolDestroy(GSTATE.masterpool_messages);

    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.masterpool_wios               = NULL;
    GSTATE.masterpool_context_pools      = NULL;
    GSTATE.masterpool_messages           = NULL;
}

static err_t wwDefaultInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp)
{
    discard inp;
    discard p;
    return 0;
}

static bool initializeMasterPools(void)
{
    master_pool_t *large    = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    master_pool_t *small    = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    master_pool_t *wios     = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    master_pool_t *contexts = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    master_pool_t *messages = masterpoolCreateWithCapacity(2 * RAM_PROFILE);

    if (UNLIKELY(large == NULL || small == NULL || wios == NULL || contexts == NULL || messages == NULL))
    {
        masterpoolDestroy(large);
        masterpoolDestroy(small);
        masterpoolDestroy(wios);
        masterpoolDestroy(contexts);
        masterpoolDestroy(messages);
        printError("GlobalState: failed to construct master-pool metadata");
        return false;
    }

    GSTATE.masterpool_buffer_pools_large = large;
    GSTATE.masterpool_buffer_pools_small = small;
    GSTATE.masterpool_wios               = wios;
    GSTATE.masterpool_context_pools      = contexts;
    GSTATE.masterpool_messages           = messages;

    workerMessagesInstallMasterPoolCallbacks(GSTATE.masterpool_messages);
    return true;
}

static bool checkedSizeProduct(size_t count, size_t element_size, size_t *out)
{
    if (element_size != 0 && count > SIZE_MAX / element_size)
    {
        return false;
    }
    *out = count * element_size;
    return true;
}

static bool initializeShortCuts(void)
{
    static const size_t kShortcutsCount = 4;

    const size_t total_workers = (size_t) WORKERS_COUNT;
    size_t       shortcut_slots;
    size_t       shortcut_bytes;
    if (UNLIKELY(! checkedSizeProduct(total_workers, kShortcutsCount, &shortcut_slots) ||
                 ! checkedSizeProduct(shortcut_slots, sizeof(void *), &shortcut_bytes)))
    {
        return false;
    }

    void **space = memoryAllocate(shortcut_bytes);
    if (UNLIKELY(space == NULL))
    {
        return false;
    }

    wloop_t                   **loops         = (wloop_t **) (space + (0 * total_workers));
    buffer_pool_t             **buffer_pools  = (buffer_pool_t **) (space + (1 * total_workers));
    threadsafe_generic_pool_t **wios_pools    = (threadsafe_generic_pool_t **) (space + (2 * total_workers));
    generic_pool_t            **context_pools = (generic_pool_t **) (space + (3 * total_workers));

    for (size_t wid = 0; wid < total_workers; wid++)
    {
        buffer_pools[wid]  = WORKERS[wid].buffer_pool;
        loops[wid]         = WORKERS[wid].loop;
        wios_pools[wid]    = WORKERS[wid].wios_pool;
        context_pools[wid] = WORKERS[wid].context_pool;
    }

    GSTATE.shortcut_loops         = loops;
    GSTATE.shortcut_buffer_pools  = buffer_pools;
    GSTATE.shortcut_wios_pools    = wios_pools;
    GSTATE.shortcut_context_pools = context_pools;
    return true;
}

static void tcpipInitDone(void *arg)
{
    discard arg;
    GSTATE.flag_lwip_initialized = 1;
    GSTATE.lwip_process_v4_hook  = wwDefaultInternalLwipIpv4Hook;
    GSTATE.lwip_wid              = getTotalWorkersCount() - 1;
    workerBindCurrentThread(getWorker(GSTATE.lwip_wid));
    frandInit();
}

// --- Public API functions ---

// could be declared in lwipopts.h
err_t wwInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp);

err_t wwInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp)
{

    return GSTATE.lwip_process_v4_hook(p, inp);
}

/*!
 * @brief Retrieves the global state.
 *
 * @return A pointer to the global state structure.
 */
ww_global_state_t *getGlobalState(void)
{
    return &GSTATE;
}

bool globalstateInitializeSecureRandom(void)
{
    secure_random_state_t *state = &GSTATE.secure_random;
    if (state->initialized)
    {
        return true;
    }

    *state = (secure_random_state_t) {0};

#if defined(OS_WIN)
    state->library_handle = LoadLibraryA("bcrypt.dll");
    if (UNLIKELY(state->library_handle == NULL))
    {
        return false;
    }

    FARPROC proc = GetProcAddress(state->library_handle, "BCryptGenRandom");
    if (UNLIKELY(proc == NULL))
    {
        FreeLibrary(state->library_handle);
        *state = (secure_random_state_t) {0};
        return false;
    }

    _Static_assert(sizeof(state->generator) == sizeof(proc), "FARPROC size mismatch");
    memoryCopy(&state->generator, &proc, sizeof(state->generator));
#elif defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
    state->device_fd = -1;
    int open_flags   = O_RDONLY;
#if defined(O_CLOEXEC)
    open_flags |= O_CLOEXEC;
#endif

    do
    {
        state->device_fd = open("/dev/urandom", open_flags);
    } while (state->device_fd < 0 && errno == EINTR);

    /* A failed open leaves the descriptor disabled.  The provider probe below
     * can still succeed through getrandom() on Linux and rejects startup when
     * no operating-system random source is available. */
#elif ! (defined(OS_DARWIN) || defined(OS_BSD))
    return false;
#endif

    state->initialized = true;

    uint8_t probe = 0;
    if (UNLIKELY(! secureRandomBytes(&probe, sizeof(probe))))
    {
        memoryZero(&probe, sizeof(probe));
        globalstateDestroySecureRandom();
        return false;
    }

    memoryZero(&probe, sizeof(probe));
    return true;
}

void globalstateDestroySecureRandom(void)
{
    secure_random_state_t *state = &GSTATE.secure_random;
    if (! state->initialized)
    {
        return;
    }

#if defined(OS_WIN)
    state->generator = NULL;
    if (state->library_handle != NULL)
    {
        FreeLibrary(state->library_handle);
    }
#elif defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
    if (state->device_fd >= 0)
    {
        discard close(state->device_fd);
    }
#endif

    memoryZero(state, sizeof(*state));
#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
    state->device_fd = -1;
#endif
}

void globalstateStopSystemLoadSampler(void)
{
    if (GSTATE.system_load != NULL)
    {
        systemLoadSamplerStop(GSTATE.system_load);
    }
}

static void globalstateRollbackConstruction(wid_t constructed_workers, bool ares_initialized, bool crypto_initialized,
                                            bool frand_initialized, bool worker_bound)
{
    if (GSTATE.system_load != NULL)
    {
        systemLoadSamplerStop(GSTATE.system_load);
        systemLoadSamplerDestroy(GSTATE.system_load);
        memoryFree(GSTATE.system_load);
        GSTATE.system_load = NULL;
    }

    socketmanagerDestroy();
    nodemanagerDestroy();
    signalmanagerDestroy();
    applicationShutdownDestroy();

    if (worker_bound)
    {
        workerUnbindCurrentThread();
    }

    memoryFree((void *) GSTATE.shortcut_loops);
    GSTATE.shortcut_loops         = NULL;
    GSTATE.shortcut_buffer_pools  = NULL;
    GSTATE.shortcut_wios_pools    = NULL;
    GSTATE.shortcut_context_pools = NULL;

    for (wid_t wid = 0; wid < constructed_workers; ++wid)
    {
        worker_t *worker     = getWorker(wid);
        worker->thread_valid = false;
        if (! atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed))
        {
            if (worker->has_event_loop)
            {
                workerDestroyUnstartedResources(worker);
            }
            else
            {
                workerDestroyPseudoWorkerResources(worker);
            }
        }
        contvarDestroy(&worker->control_condition);
        condmutexDestroy(&worker->control_condition_mutex);
        mutexDestroy(&worker->control_mutex);
    }

    memoryFree(WORKERS);
    WORKERS              = NULL;
    GSTATE.workers_count = 0;
    globalstateDestroyMasterPools();

    coreloggerDestroy();
    networkloggerDestroy();
    dnsloggerDestroy();
    internaloggerDestroy();
    loggerDestroyDefaultLogger();

    if (ares_initialized)
    {
        ares_library_cleanup();
    }
    if (crypto_initialized)
    {
        wCryptoGlobalCleanup();
    }
    if (frand_initialized)
    {
        frandThreadCleanup();
        frandGlobalCleanup();
    }
    globalstateDestroySecureRandom();
    GSTATE = (ww_global_state_t) {0};
}

/*!
 * @brief Sets the global state.
 *
 * This function sets the global state and initializes related components like loggers, signal manager, socket manager,
 * and node manager. It asserts that the global state is not already initialized before setting it.
 *
 * @param state A pointer to the global state structure to be set.
 */
void setGlobalState(struct ww_global_state_s *state)
{
    assert(! GSTATE.flag_initialized && state->flag_initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setInternalLogger(GSTATE.internal_logger);
    applicationShutdownSet(GSTATE.application_shutdown);
    signalmanagerSet(GSTATE.signal_manager);
    socketmanagerSet(GSTATE.socekt_manager);
    nodemanagerSetState(GSTATE.node_manager);
}

/*!
 * @brief Updates the allocation padding for all worker buffer pools.
 *
 * This function updates the allocation padding for each worker's buffer pool. It is used to adjust memory allocation
 * sizes.
 *
 * @param padding The padding value to be applied to the buffer pools.
 */
void globalstateUpdateAllocationPadding(uint16_t padding)
{
    for (wid_t wi = 0; wi < getTotalWorkersCount(); wi++)
    {
        bufferpoolUpdateAllocationPaddings(getWorkerBufferPool(wi), padding, padding);
    }
}

/*!
 * @brief Creates the global state and initializes the WaterWall instance.
 *
 * This function creates the global state, initializes loggers, workers, pools, and managers.
 * It also initializes the crypto backend (OpenSSL or Sodium) and spawns worker threads.
 *
 * @param init_data The construction data for the global state, including logger configurations and worker counts.
 */
ww_startup_result_t createGlobalState(const ww_construction_data_t init_data)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    bool  crypto_initialized  = false;
    bool  ares_initialized    = false;
    bool  frand_initialized   = false;
    bool  worker_bound        = false;
    wid_t constructed_workers = 0;

    GSTATE                       = (ww_global_state_t) {0};
    GSTATE.flag_initialized      = true;
    GSTATE.main_thread_id        = (uint64_t) getTID();
    GSTATE.dns_options           = init_data.dns_options;
    GSTATE.domain_strategy       = init_data.domain_strategy;
    GSTATE.application_finalizer = init_data.application_finalizer;
    if (! GSTATE.dns_options.defaults_initialized)
    {
        asyncdnsOptionsSetDefaults(&GSTATE.dns_options);
    }
    atomicStoreRelaxed(&GSTATE.workers_run_flag, false);

    if (UNLIKELY(! globalstateInitializeSecureRandom()))
    {
        printError("Failed to initialize the operating-system secure random provider\n");
        startupFailureRecord(1);
        goto rollback;
    }

    if (UNLIKELY(! frandGlobalInit()))
    {
        printError("Failed to initialize process fast-random state\n");
        startupFailureRecord(1);
        goto rollback;
    }
    frand_initialized = true;
    frandInit();

    /* Initialize cryptography before any other process-wide subsystem.  If a
     * backend cannot start, there are no workers, managers, loggers, or c-ares
     * resources to unwind and no consumer can observe a partially initialized
     * crypto runtime. */
    const wcrypto_status_t crypto_status = wCryptoGlobalInit();
    if (crypto_status != kWCryptoOk)
    {
        printError("Failed to initialize cryptography: %s\n", wCryptoStatusString(crypto_status));
        startupFailureRecord(1);
        goto rollback;
    }
    crypto_initialized = true;

    int ares_rc = ares_library_init(ARES_LIB_INIT_ALL);
    if (ares_rc != ARES_SUCCESS)
    {
        printError("Failed to initialize c-ares: %s\n", ares_strerror(ares_rc));
        startupFailureRecord(1);
        goto rollback;
    }
    ares_initialized = true;

    // [Section] loggers
    {
        GSTATE.internal_logger = createInternalLogger(init_data.internal_logger_data.log_file_path,
                                                      init_data.internal_logger_data.log_console);
        if (UNLIKELY(GSTATE.internal_logger == NULL))
        {
            printError("GlobalState: failed to construct internal logger\n");
            startupFailureRecord(1);
            goto rollback;
        }
        stringUpperCase(init_data.internal_logger_data.log_level);
        setInternalLoggerLevelByStr(init_data.internal_logger_data.log_level);

        GSTATE.core_logger =
            createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);
        if (UNLIKELY(GSTATE.core_logger == NULL))
        {
            printError("GlobalState: failed to construct core logger\n");
            startupFailureRecord(1);
            goto rollback;
        }

        stringUpperCase(init_data.core_logger_data.log_level);
        setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);

        GSTATE.network_logger =
            createNetworkLogger(init_data.network_logger_data.log_file_path, init_data.network_logger_data.log_console);
        if (UNLIKELY(GSTATE.network_logger == NULL))
        {
            printError("GlobalState: failed to construct network logger\n");
            startupFailureRecord(1);
            goto rollback;
        }

        stringUpperCase(init_data.network_logger_data.log_level);
        setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

        GSTATE.dns_logger =
            createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);
        if (UNLIKELY(GSTATE.dns_logger == NULL))
        {
            printError("GlobalState: failed to construct DNS logger\n");
            startupFailureRecord(1);
            goto rollback;
        }

        stringUpperCase(init_data.dns_logger_data.log_level);
        setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
    }

    // workers and pools creation
    {
        _Static_assert((MAX_ORDINARY_WORKERS + WORKER_ADDITIONS) <= kInvalidWID,
                       "Max workers count must not reach kInvalidWID");

        WORKERS_COUNT         = init_data.workers_count;
        GSTATE.ram_profile    = init_data.ram_profile;
        GSTATE.distribute_wid = 0;

        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > MAX_ORDINARY_WORKERS)
        {
            LOGW("workers count was not in valid range, value: %u range:[1 - %d]\n",
                 WORKERS_COUNT,
                 MAX_ORDINARY_WORKERS);
            WORKERS_COUNT = MAX_ORDINARY_WORKERS;
        }
        WORKERS_COUNT += WORKER_ADDITIONS;

        size_t worker_bytes;
        if (UNLIKELY(! checkedSizeProduct((size_t) WORKERS_COUNT, sizeof(worker_t), &worker_bytes)))
        {
            LOGF("GlobalState: worker registry size overflow");
            startupFailureRecord(1);
            goto rollback;
        }
        worker_t *workers = memoryAllocate(worker_bytes);
        if (UNLIKELY(workers == NULL))
        {
            LOGF("GlobalState: failed to allocate worker registry");
            startupFailureRecord(1);
            goto rollback;
        }
        WORKERS = workers;

        if (UNLIKELY(! initializeMasterPools()))
        {
            startupFailureRecord(1);
            goto rollback;
        }

        for (wid_t i = 0; i < getWorkersCount(); ++i)
        {
            if (UNLIKELY(! workerInit(getWorker(i), i, true)))
            {
                constructed_workers = i + 1;
                startupFailureRecord(1);
                goto rollback;
            }
            constructed_workers = i + 1;
        }

        // WORKER_ADDITIONS 1 : lwip worker dose not have event loop
        if (UNLIKELY(! workerInit(getWorker(getTotalWorkersCount() - 1), getTotalWorkersCount() - 1, false)))
        {
            constructed_workers = getTotalWorkersCount();
            startupFailureRecord(1);
            goto rollback;
        }
        constructed_workers = getTotalWorkersCount();

        worker_t *worker0 = getWorker(0);
        workerBindCurrentThread(worker0);
        worker_bound = true;

        if (UNLIKELY(! initializeShortCuts()))
        {
            LOGF("GlobalState: failed to allocate worker shortcut registry");
            startupFailureRecord(1);
            goto rollback;
        }

        system_load_state_t *system_load = memoryAllocateZero(sizeof(*system_load));
        if (system_load != NULL && systemLoadSamplerTryInit(system_load))
        {
            GSTATE.system_load = system_load;
            if (UNLIKELY(! systemLoadSamplerStart(system_load, getWorkerLoop(0))))
            {
                LOGW("System load sampler could not start; overload checks will use fail-closed cache semantics");
            }
        }
        else
        {
            memoryFree(system_load);
            GSTATE.system_load = NULL;
            LOGW("System load sampler metadata is unavailable; overload checks are disabled");
        }
    }

    // managers
    {
        GSTATE.application_shutdown = applicationShutdownCreate();
        GSTATE.signal_manager       = signalmanagerCreate();
        GSTATE.socekt_manager       = socketmanagerCreate();
        GSTATE.node_manager         = nodemanagerCreate();
        if (UNLIKELY(GSTATE.application_shutdown == NULL || GSTATE.signal_manager == NULL ||
                     GSTATE.socekt_manager == NULL || GSTATE.node_manager == NULL))
        {
            LOGF("GlobalState: failed to construct mandatory manager metadata");
            startupFailureRecord(1);
            goto rollback;
        }
    }
    // misc
    {
        GSTATE.capturedevice_queue_start_number = fastRand() % 2000;
        GSTATE.mtu_size                         = init_data.mtu_size;
    }

    // Spawn all workers except main worker which is current thread
    {
        worker_t *worker0 = getWorker(0);
#ifdef OS_WIN
        worker0->thread = (wthread_t) GetCurrentThread();
#else
        worker0->thread = pthread_self();
#endif
        worker0->thread_valid = true;

        // Block graceful (shutdown-routed) signals on the main thread before
        // spawning workers, so the workers inherit the blocked mask; the main
        // thread re-enables them in signalmanagerStart(). This keeps graceful
        // signal delivery on the main thread and out of the worker event loops.
        signalmanagerBlockHandledSignalsForCurrentThread();

        // lwip worker dose not need spawn, it runs its own eventloop
        for (unsigned int i = 1; i < WORKERS_COUNT - WORKER_ADDITIONS; ++i)
        {
            wthread_error_t error = workerSpawn(&WORKERS[i]);
            if (UNLIKELY(error != kWThreadErrorNone))
            {
#ifdef OS_WIN
                LOGF("Failed to create worker %u thread: error %u", i, error);
#else
                LOGF("Failed to create worker %u thread: error %u (%s)", i, error, strerror((int) error));
#endif
                globalstateDestroyWorkersThatNeverStarted((wid_t) i);
                startupFailureRecord(1);
                return wwStartupContextEnd(&startup);
            }
        }
    }

    if (UNLIKELY(! signalmanagerStart()))
    {
        startupFailureRecord(1);
        return wwStartupContextEnd(&startup);
    }
    return wwStartupContextEnd(&startup);

rollback:
    globalstateRollbackConstruction(
        constructed_workers, ares_initialized, crypto_initialized, frand_initialized, worker_bound);
    return wwStartupContextEnd(&startup);
}

static void globalstateRequireWorkerPhase(worker_lifecycle_e phase)
{
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed))
        {
            continue;
        }
        if (! workerWaitForPhase(worker, phase, 30000))
        {
            LOGF("Worker %d did not acknowledge lifecycle phase %d", workerWIDForLog(wid), (int) phase);
            abortProgramNow(1);
        }
    }
}

static void globalstateDestroyWorkersThatNeverStarted(wid_t first)
{
    for (wid_t wid = first; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (! worker->thread_valid && workerGetLifecycle(worker) == kWorkerLifecycleInitialized)
        {
            workerDestroyUnstartedResources(worker);
        }
    }
}

void globalstateRunShutdownSequence(void)
{
    assert((uint64_t) getTID() == GSTATE.main_thread_id);

    ww_lifecycle_context_t context;
    if (! applicationShutdownGetSelectedContext(&context))
    {
        LOGF("Application shutdown has no selected lifecycle context");
        abortProgramNow(1);
    }

    nodemanagerQuiesceRequest(&context);
    for (wid_t wid = 1; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (! atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed))
        {
            discard workerRequestQuiesceWithContext(worker, &context);
        }
    }

    applicationShutdownAdvancePhase(kApplicationShutdownQuiescingWorkers);
    workerPerformQuiesce(getWorker(0), &context);
    globalstateRequireWorkerPhase(kWorkerLifecycleQuiesced);

    applicationShutdownAdvancePhase(kApplicationShutdownQuiescingExternalProducers);
    nodemanagerQuiesceWait(&context);

    applicationShutdownAdvancePhase(kApplicationShutdownDrainingWorkers);
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed))
        {
            continue;
        }
        if (! workerRequestDrain(worker))
        {
            LOGF("Worker %d could not enter the drain phase", workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }
    workerPerformDrain(getWorker(0), &context);
    globalstateRequireWorkerPhase(kWorkerLifecycleDrained);

    applicationShutdownAdvancePhase(kApplicationShutdownStoppingComponents);
    nodemanagerStop(&context);

    applicationShutdownAdvancePhase(kApplicationShutdownDestroyingWorkers);
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed))
        {
            continue;
        }
        if (! workerRequestTeardown(worker))
        {
            LOGF("Worker %d could not enter the teardown phase", workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }
    workerPerformTeardown(getWorker(0));
    globalstateRequireWorkerPhase(kWorkerLifecycleExited);

    for (wid_t wid = 1; wid < getWorkersCount(); ++wid)
    {
        worker_t *worker = getWorker(wid);
        if (! workerJoin(worker))
        {
            LOGF("Failed to join worker %d during terminal shutdown", workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }

    if (GSTATE.flag_lwip_initialized)
    {
        if (! wwLwipShutdown())
        {
            LOGF("Failed to quiesce and join the lwIP tcpip thread");
            abortProgramNow(1);
        }
        GSTATE.flag_lwip_initialized = 0;
    }
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));

    signalmanagerRunExitObservers();
    if (GSTATE.application_finalizer != NULL)
    {
        GSTATE.application_finalizer();
        GSTATE.application_finalizer = NULL;
    }
}

/*!
 * @brief Runs the main thread's event loop.
 *
 * This function runs the event loop for the main worker thread. It asserts that the global state is initialized.
 * After the main loop finishes, it joins all other worker threads and exits.
 * it also allows other workers begin their loops.
 */
void runMainThread(void)
{
    assert(GSTATE.flag_initialized);

    signalmanagerConsumePendingShutdownSignal();
    if (! applicationShutdownCommitRuntime())
    {
        applicationShutdownCoordinate();
        abortProgramNow(1);
    }

    // Publishes fully initialized global/worker state before spawned loops run.
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);

    workerRun(getWorker(0));
    signalmanagerConsumePendingShutdownSignal();
    applicationShutdownCoordinate();
    abortProgramNow(1);
}

/*!
 * @brief destroys global state and ends the program
 *
 * Runs on the main thread at the end of the shutdown sequence, once every other
 * worker has been stopped and joined.
 */
void finishGlobalState(const application_shutdown_snapshot_t *snapshot)
{
    assert((uint64_t) getTID() == GSTATE.main_thread_id);
    assert(snapshot != NULL);
    const int exit_code = snapshot->exit_code;
    destroyGlobalState();

    exit(exit_code);
}

void initTcpIpStack(void)
{
    assert(GSTATE.flag_initialized);
    if (GSTATE.flag_lwip_initialized)
    {
        return;
    }
    GSTATE.flag_lwip_initialized = 1;
    tcpipInit(tcpipInitDone, NULL);
}

extern void call_freeres(void);

WW_EXPORT void destroyGlobalState(void)
{
    socketmanagerDestroy();
    nodemanagerDestroy();
#if defined(OS_WIN)
    tundevicePlatformShutdown();
#endif
    wCryptoGlobalCleanup();

    coreloggerDestroy();
    networkloggerDestroy();
    dnsloggerDestroy();
    internaloggerDestroy();
    loggerDestroyDefaultLogger();

    globalstateDestroyMasterPools();

    memoryFree((void *) GSTATE.shortcut_loops);
    GSTATE.shortcut_loops         = NULL;
    GSTATE.shortcut_buffer_pools  = NULL;
    GSTATE.shortcut_wios_pools    = NULL;
    GSTATE.shortcut_context_pools = NULL;

    if (WORKERS != NULL)
    {
        // Every worker has been stopped and joined by now, so no thread can
        // still take a worker control mutex.
        for (wid_t wi = 0; wi < getTotalWorkersCount(); wi++)
        {
            contvarDestroy(&getWorker(wi)->control_condition);
            condmutexDestroy(&getWorker(wi)->control_condition_mutex);
            mutexDestroy(&getWorker(wi)->control_mutex);
        }
    }

    nodelibraryCleanup();

    ares_library_cleanup();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    if (GSTATE.system_load != NULL)
    {
        systemLoadSamplerDestroy(GSTATE.system_load);
        memoryFree(GSTATE.system_load);
        GSTATE.system_load = NULL;
    }

    signalmanagerDestroy();
    applicationShutdownDestroy();

    workerUnbindCurrentThread();
    memoryFree(WORKERS);
    WORKERS              = NULL;
    GSTATE.workers_count = 0;

#ifdef WW_CALL_GNU_FREES
    call_freeres();
#endif
}

_Noreturn void globalstateAbortNotEventWorker(const char *accessor)
{
    const wid_t wid = getWID();

    LOGF("%s: caller is not an ordinary event worker (wid %d, tid %llu)",
         accessor,
         workerWIDForLog(wid),
         (unsigned long long) getTID());

    abortProgramNow(1);
}

void reuseBuffer(sbuf_t *b)
{
    assert(b != NULL);

    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), b);
}
