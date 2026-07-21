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

#include <ares.h>

#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(WCRYPTO_USING_OPENSSL)

#include "crypto/openssl_instance.h"

#endif

#if defined(WCRYPTO_BACKEND_SODIUM)

#include "crypto/sodium_instance.h"

#endif

#if defined(WCRYPTO_BACKEND_SOFTWARE)

#endif

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
    GSTATE.masterpool_buffer_pools_large = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_buffer_pools_small = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_wios               = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_context_pools      = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_messages           = masterpoolCreateWithCapacity(2 * RAM_PROFILE);

    workerMessagesInstallMasterPoolCallbacks(GSTATE.masterpool_messages);
}

static void initializeShortCuts(void)
{
    static const int kShortcutsCount = 4;

    const uintptr_t total_workers = (uintptr_t) WORKERS_COUNT;

    void **space = (void **) memoryAllocate(sizeof(void *) * (uintptr_t) kShortcutsCount * total_workers);

    GSTATE.shortcut_loops         = (wloop_t **) (space + (0 * total_workers));
    GSTATE.shortcut_buffer_pools  = (buffer_pool_t **) (space + (1 * total_workers));
    GSTATE.shortcut_wios_pools    = (threadsafe_generic_pool_t **) (space + (2 * total_workers));
    GSTATE.shortcut_context_pools = (generic_pool_t **) (space + (3 * total_workers));

    for (unsigned int wid = 0; wid < total_workers; wid++)
    {

        GSTATE.shortcut_buffer_pools[wid]  = WORKERS[wid].buffer_pool;
        GSTATE.shortcut_loops[wid]         = WORKERS[wid].loop;
        GSTATE.shortcut_wios_pools[wid]    = WORKERS[wid].wios_pool;
        GSTATE.shortcut_context_pools[wid] = WORKERS[wid].context_pool;
    }
}

static void exitHandle(void *userdata, int signum)
{
    discard signum;
    discard userdata;

    nodemanagerStop();

    // notify all worker threads that were spawned via workerSpawn() before joining any of them
    for (unsigned int wid = 1; wid < WORKERS_COUNT - WORKER_ADDITIONS; ++wid)
    {
        workerFinish(getWorker(wid));
    }
    // join only worker threads that were spawned via workerSpawn()
    for (unsigned int wid = 1; wid < WORKERS_COUNT - WORKER_ADDITIONS; ++wid)
    {
        workerJoin(getWorker(wid));
    }
    // lwip pseudo-worker has no spawned OS thread, but it still owns pools
    workerFinish(getWorker(getTotalWorkersCount() - 1));

    if (getTID() == getWorker(0)->tid)
    {
        // we are in the main thread, so we can finish the worker and tear down the global state
        workerFinish(getWorker(0));
        finishGlobalState();
    }
    else
    {
        // when main thread finishes it will tear down the global state
        workerFinish(getWorker(0));
        workerJoin(getWorker(0));
    }
}

static void tcpipInitDone(void *arg)
{
    discard arg;
    GSTATE.flag_lwip_initialized = 1;
    GSTATE.lwip_process_v4_hook  = wwDefaultInternalLwipIpv4Hook;
    // lwip thread worker id is set to invalid value (larger than workers 0 index)
    tl_wid          = getTotalWorkersCount() - 1; // lwip is the last worker
    GSTATE.lwip_wid = tl_wid;
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
    int open_flags = O_RDONLY;
#if defined(O_CLOEXEC)
    open_flags |= O_CLOEXEC;
#endif

    do
    {
        state->device_fd = open("/dev/urandom", open_flags);
    } while (state->device_fd < 0 && errno == EINTR);

    if (UNLIKELY(state->device_fd < 0))
    {
        return false;
    }
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
    GSTATE.main_thread_id = (uint64_t) getTID();
    GSTATE.dns_options    = init_data.dns_options;
    GSTATE.domain_strategy  = init_data.domain_strategy;
    if (! GSTATE.dns_options.defaults_initialized)
    {
        asyncdnsOptionsSetDefaults(&GSTATE.dns_options);
    }
    atomicStoreRelaxed(&GSTATE.application_stopping_flag, false);
    atomicStoreRelaxed(&GSTATE.workers_run_flag, false);

    if (UNLIKELY(! globalstateInitializeSecureRandom()))
    {
        printError("Failed to initialize the operating-system secure random provider\n");
        terminateProgram(1);
    }

    int ares_rc = ares_library_init(ARES_LIB_INIT_ALL);
    if (ares_rc != ARES_SUCCESS)
    {
        printError("Failed to initialize c-ares: %s\n", ares_strerror(ares_rc));
        terminateProgram(1);
    }

    // [Section] loggers
    {
        GSTATE.internal_logger = createInternalLogger(init_data.internal_logger_data.log_file_path,
                                                      init_data.internal_logger_data.log_console);
        stringUpperCase(init_data.internal_logger_data.log_level);
        setInternalLoggerLevelByStr(init_data.internal_logger_data.log_level);

        GSTATE.core_logger =
            createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);

        stringUpperCase(init_data.core_logger_data.log_level);
        setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);

        GSTATE.network_logger =
            createNetworkLogger(init_data.network_logger_data.log_file_path, init_data.network_logger_data.log_console);

        stringUpperCase(init_data.network_logger_data.log_level);
        setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

        GSTATE.dns_logger =
            createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);

        stringUpperCase(init_data.dns_logger_data.log_level);
        setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
    }

    // workers and pools creation
    {
        WORKERS_COUNT         = init_data.workers_count;
        GSTATE.ram_profile    = init_data.ram_profile;
        GSTATE.distribute_wid = 0;

        // this check was required to avoid overflow in older version when workers_count was limited to 254
        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (254))
        {
            LOGW("workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT, (254));
            WORKERS_COUNT = (254);
        }
        WORKERS_COUNT += WORKER_ADDITIONS;

        WORKERS = (worker_t *) memoryAllocate(sizeof(worker_t) * (WORKERS_COUNT));

        initializeMasterPools();

        for (wid_t i = 0; i < getWorkersCount(); ++i)
        {
            workerInit(getWorker(i), i, true);
        }

        // WORKER_ADDITIONS 1 : lwip worker dose not have event loop
        workerInit(getWorker(getTotalWorkersCount() - 1), getTotalWorkersCount() - 1, false);

        initializeShortCuts();
    }

    // managers
    {
        GSTATE.signal_manager = signalmanagerCreate();
        GSTATE.socekt_manager = socketmanagerCreate();
        GSTATE.node_manager   = nodemanagerCreate();
    }
    // misc
    {
        GSTATE.capturedevice_queue_start_number = fastRand() % 2000;
        GSTATE.mtu_size                         = init_data.mtu_size;
    }

    // SSL
    {

// later we gona brind openssl anyway...
#if defined(WCRYPTO_USING_OPENSSL)

        opensslGlobalInit();
        GSTATE.flag_openssl_initialized = true;

#endif

#if defined(WCRYPTO_BACKEND_SODIUM)

        const int sodium_result = initSodium();
        if (sodium_result < 0)
        {
            printError("Failed to initialize libsodium\n");
            terminateProgram(1);
        }
        GSTATE.flag_libsodium_initialized = true;
#endif
    }

    // Spawn all workers except main worker which is current thread
    {
        worker_t *worker = getWorker(0);
#ifdef OS_WIN
        worker->thread = (wthread_t) GetCurrentThread();
#else
        worker->thread = pthread_self();
#endif
        worker->tid = getTID();

        // Block graceful (shutdown-routed) signals on the main thread before
        // spawning workers, so the workers inherit the blocked mask; the main
        // thread re-enables them in signalmanagerStart(). This keeps graceful
        // signal delivery on the main thread and out of the worker event loops.
        signalmanagerBlockHandledSignalsForCurrentThread();

        // lwip worker dose not need spawn, it runs its own eventloop
        for (unsigned int i = 1; i < WORKERS_COUNT - WORKER_ADDITIONS; ++i)
        {
            workerSpawn(&WORKERS[i]);
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

    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);

    workerRun(getWorker(0));

    finishGlobalState();

    // if we return right here the main thread exits and program finishes
    // but the thread that requested our exit may still have work to do
    // wwSleepMS(2000);
    // LOGD("MainThread Returned");
}

/*!
 * @brief destroys global state and ends the program
 *
 */
void finishGlobalState(void)
{
    // its not important which thread called this, at this point only 1 thread is running
    assert(isApplicationTerminating());
    const int exit_code = signalmanagerGetExitCode();
    nodemanagerStop();
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
#if defined(WCRYPTO_USING_OPENSSL)
    opensslGlobalCleanup();
#endif

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

    memoryFree(WORKERS);
    WORKERS = NULL;

    nodelibraryCleanup();

    ares_library_cleanup();

    globalstateDestroySecureRandom();

    signalmanagerDestroy();

#ifdef WW_CALL_GNU_FREES
    call_freeres();
#endif
}

void reuseBuffer(sbuf_t *b)
{
    assert(b != NULL);

    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), b);
}
