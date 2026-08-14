#include "global_state.h"
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(OS_UNIX)
#include <string.h>
#endif

#include "crypto/wcrypto.h"

// Global instance of the ww_global_state_t structure.
ww_global_state_t global_ww_state = {0};

// --- Static helper functions ---

static err_t wwDefaultInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp)
{
    discard inp;
    discard p;
    return 0;
}

static void initializeMasterPools(void)
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
        abortProgramNow(1);
    }

    GSTATE.masterpool_buffer_pools_large = large;
    GSTATE.masterpool_buffer_pools_small = small;
    GSTATE.masterpool_wios               = wios;
    GSTATE.masterpool_context_pools      = contexts;
    GSTATE.masterpool_messages           = messages;

    workerMessagesInstallMasterPoolCallbacks(GSTATE.masterpool_messages);
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

/*
 * Global-state shutdown callback. Registered first, so the LIFO registry runs it
 * last, after every other subsystem callback has had the workers available.
 *
 * It always runs on worker 0 / the main thread: the shutdown manager guarantees
 * the callback traversal happens there, which is what makes joining the other
 * workers safe (a worker can never end up joining itself or waiting for a lock
 * it holds).
 */
static void exitHandle(void *userdata, int signum)
{
    discard signum;
    discard userdata;

    assert((uint64_t) getTID() == GSTATE.main_thread_id);

    // Node stop hooks, external cleanup scripts and device shutdown run exactly
    // once; nodemanagerStop() is idempotent and this is its only normal caller.
    nodemanagerStop();

    // Ask every spawned worker to stop before joining the first one, so shutdown
    // does not serialize on one slow worker.
    for (unsigned int wid = 1; wid < WORKERS_COUNT - WORKER_ADDITIONS; ++wid)
    {
        discard workerRequestStop(getWorker(wid));
    }
    // join only worker threads that were spawned via workerSpawn(); each of them
    // destroyed its own event-loop-local resources before returning.
    for (unsigned int wid = 1; wid < WORKERS_COUNT - WORKER_ADDITIONS; ++wid)
    {
        if (UNLIKELY(! workerJoin(getWorker(wid))))
        {
            /*
             * A possibly-live worker still owns worker-local and global
             * resources. Continuing into pool/manager destruction would turn a
             * join failure into use-after-free, so terminal shutdown must stop
             * here instead of pretending ownership transferred.
             */
            LOGF("Failed to join worker %u during terminal shutdown", wid);
            abortProgramNow(1);
        }
    }

    /*
     * Worker 0 was not spawned, so the join loop above cannot quiesce its
     * tunnel callbacks. Destroy its event-loop-local resources now: onWorkerStop
     * may still close live connections through lwIP and must run while the core
     * lock exists.
     */
    workerDestroyOwnResources(getWorker(0));

    /*
     * tcpip_init() owns a real OS thread even though WaterWall models its pools
     * as a pseudo-worker. All ordinary workers are now quiescent, so the
     * remaining lwIP work can be drained while every global and pseudo-worker
     * resource it can reference is still alive.
     */
    if (GSTATE.flag_lwip_initialized)
    {
        if (UNLIKELY(! wwLwipShutdown()))
        {
            LOGF("Failed to quiesce and join the lwIP tcpip thread");
            abortProgramNow(1);
        }
        GSTATE.flag_lwip_initialized = 0;
    }
    // The joined lwIP thread has no WaterWall event loop. Its pseudo-worker
    // pools can now be destroyed explicitly without a late pbuf callback.
    workerDestroyOwnResources(getWorker(getTotalWorkersCount() - 1));

    finishGlobalState();
}

static void tcpipInitDone(void *arg)
{
    discard arg;
    GSTATE.flag_lwip_initialized = 1;
    GSTATE.lwip_process_v4_hook  = wwDefaultInternalLwipIpv4Hook;
    GSTATE.lwip_wid              = getTotalWorkersCount() - 1;
    workerBindCurrentThread(getWorker(GSTATE.lwip_wid));
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
    GSTATE.flag_buffers_calculated = true;
}

/*!
 * @brief Creates the global state and initializes the WaterWall instance.
 *
 * This function creates the global state, initializes loggers, workers, pools, and managers.
 * It also initializes the crypto backend (OpenSSL or Sodium) and spawns worker threads.
 *
 * @param init_data The construction data for the global state, including logger configurations and worker counts.
 */
void createGlobalState(const ww_construction_data_t init_data)
{
    GSTATE = (ww_global_state_t) {0};

    GSTATE.flag_initialized = true;
    // Capture the main thread id early so terminateProgram()/the shutdown handoff
    // can reliably tell whether it runs on the main worker thread, even during
    // startup before workers are spawned.
    GSTATE.main_thread_id  = (uint64_t) getTID();
    GSTATE.dns_options     = init_data.dns_options;
    GSTATE.domain_strategy = init_data.domain_strategy;
    if (! GSTATE.dns_options.defaults_initialized)
    {
        asyncdnsOptionsSetDefaults(&GSTATE.dns_options);
    }
    atomicStoreRelaxed(&GSTATE.application_stopping_flag, false);
    atomicStoreRelaxed(&GSTATE.workers_run_flag, false);

    if (UNLIKELY(! globalstateInitializeSecureRandom()))
    {
        printError("Failed to initialize the operating-system secure random provider\n");
        GSTATE = (ww_global_state_t) {0};
        terminateProgram(1);
    }

    /* Initialize cryptography before any other process-wide subsystem.  If a
     * backend cannot start, there are no workers, managers, loggers, or c-ares
     * resources to unwind and no consumer can observe a partially initialized
     * crypto runtime. */
    const wcrypto_status_t crypto_status = wCryptoGlobalInit();
    if (crypto_status != kWCryptoOk)
    {
        printError("Failed to initialize cryptography: %s\n", wCryptoStatusString(crypto_status));
        wCryptoGlobalCleanup();
        globalstateDestroySecureRandom();
        GSTATE = (ww_global_state_t) {0};
        terminateProgram(1);
    }

    int ares_rc = ares_library_init(ARES_LIB_INIT_ALL);
    if (ares_rc != ARES_SUCCESS)
    {
        printError("Failed to initialize c-ares: %s\n", ares_strerror(ares_rc));
        wCryptoGlobalCleanup();
        globalstateDestroySecureRandom();
        GSTATE = (ww_global_state_t) {0};
        terminateProgram(1);
    }

    // [Section] loggers
    {
        GSTATE.internal_logger = createInternalLogger(init_data.internal_logger_data.log_file_path,
                                                      init_data.internal_logger_data.log_console);
        if (UNLIKELY(GSTATE.internal_logger == NULL))
        {
            printError("GlobalState: failed to construct internal logger\n");
            terminateProgram(1);
        }
        stringUpperCase(init_data.internal_logger_data.log_level);
        setInternalLoggerLevelByStr(init_data.internal_logger_data.log_level);

        GSTATE.core_logger =
            createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);
        if (UNLIKELY(GSTATE.core_logger == NULL))
        {
            printError("GlobalState: failed to construct core logger\n");
            terminateProgram(1);
        }

        stringUpperCase(init_data.core_logger_data.log_level);
        setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);

        GSTATE.network_logger =
            createNetworkLogger(init_data.network_logger_data.log_file_path, init_data.network_logger_data.log_console);
        if (UNLIKELY(GSTATE.network_logger == NULL))
        {
            printError("GlobalState: failed to construct network logger\n");
            terminateProgram(1);
        }

        stringUpperCase(init_data.network_logger_data.log_level);
        setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

        GSTATE.dns_logger =
            createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);
        if (UNLIKELY(GSTATE.dns_logger == NULL))
        {
            printError("GlobalState: failed to construct DNS logger\n");
            terminateProgram(1);
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
            terminateProgram(1);
        }
        worker_t *workers = memoryAllocate(worker_bytes);
        if (UNLIKELY(workers == NULL))
        {
            LOGF("GlobalState: failed to allocate worker registry");
            terminateProgram(1);
        }
        WORKERS = workers;

        initializeMasterPools();

        for (wid_t i = 0; i < getWorkersCount(); ++i)
        {
            workerInit(getWorker(i), i, true);
        }

        // WORKER_ADDITIONS 1 : lwip worker dose not have event loop
        workerInit(getWorker(getTotalWorkersCount() - 1), getTotalWorkersCount() - 1, false);

        worker_t *worker0 = getWorker(0);
#ifdef OS_WIN
        worker0->thread = (wthread_t) GetCurrentThread();
#else
        worker0->thread = pthread_self();
#endif
        worker0->thread_valid = true;

        workerBindCurrentThread(worker0);

        if (UNLIKELY(! initializeShortCuts()))
        {
            LOGF("GlobalState: failed to allocate worker shortcut registry");
            terminateProgram(1);
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
        GSTATE.signal_manager = signalmanagerCreate();
        GSTATE.socekt_manager = socketmanagerCreate();
        GSTATE.node_manager   = nodemanagerCreate();
        if (UNLIKELY(GSTATE.signal_manager == NULL || GSTATE.socekt_manager == NULL || GSTATE.node_manager == NULL))
        {
            LOGF("GlobalState: failed to construct mandatory manager metadata");
            terminateProgram(1);
        }
    }
    // misc
    {
        GSTATE.capturedevice_queue_start_number = fastRand() % 2000;
        GSTATE.mtu_size                         = init_data.mtu_size;
    }

    // Spawn all workers except main worker which is current thread
    {
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
                terminateProgram(1);
            }
        }
    }

    registerAtExitCallBack(exitHandle, NULL);
    signalmanagerStart();
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

    // Publishes fully initialized global/worker state before spawned loops run.
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);

    workerRun(getWorker(0));

    /*
     * Worker 0's loop returned without the shutdown executor terminating the
     * process. That is the unexpected path (the normal one exits from inside the
     * worker-0 shutdown callback), so run the once-only main-thread shutdown
     * here rather than skipping the registered cleanup. It normally does not
     * return; finishGlobalState() below only covers a shutdown pass that was
     * already claimed.
     */
    signalmanagerRunShutdownOnMainThread();

    finishGlobalState();
}

/*!
 * @brief destroys global state and ends the program
 *
 * Runs on the main thread at the end of the shutdown sequence, once every other
 * worker has been stopped and joined.
 */
void finishGlobalState(void)
{
    // its not important which thread called this, at this point only 1 thread is running
    assert(isApplicationTerminating());

    // Node stop hooks already ran in the shutdown callback; nodemanagerStop() is
    // deliberately not called a second time here.
    signalmanagerEnterFinalizing();

    const int exit_code = signalmanagerGetExitCode();
    atomicThreadFence(memory_order_seq_cst);
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
            mutexDestroy(&getWorker(wi)->control_mutex);
        }
    }

    nodelibraryCleanup();

    ares_library_cleanup();

    globalstateDestroySecureRandom();
    if (GSTATE.system_load != NULL)
    {
        systemLoadSamplerDestroy(GSTATE.system_load);
        memoryFree(GSTATE.system_load);
        GSTATE.system_load = NULL;
    }

    signalmanagerDestroy();

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
