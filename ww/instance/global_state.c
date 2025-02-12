#include "global_state.h"
#include "buffer_pool.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"

#if defined(WCRYPTO_BACKEND_OPENSSL)

#include "crypto/openssl_instance.h"

#elif defined(WCRYPTO_BACKEND_SODIUM)

#include "crypto/sodium_instance.h"

#elif defined(WCRYPTO_BACKEND_SOFTWARE)

#else

#error "No crypto backend defined"

#endif

// Global instance of the ww_global_state_t structure.
ww_global_state_t global_ww_state = {0};

/*!
 * @brief Retrieves the global state.
 *
 * @return A pointer to the global state structure.
 */
ww_global_state_t *globalStateGet(void)
{
    return &GSTATE;
}

/*!
 * @brief Sets the global state.
 *
 * This function sets the global state and initializes related components like loggers, signal manager, socket manager,
 * and node manager. It asserts that the global state is not already initialized before setting it.
 *
 * @param state A pointer to the global state structure to be set.
 */
void globalStateSet(struct ww_global_state_s *state)
{
    assert(! GSTATE.flag_initialized && state->flag_initialized);
    GSTATE = *state;

    setCoreLogger(GSTATE.core_logger);
    setNetworkLogger(GSTATE.network_logger);
    setDnsLogger(GSTATE.dns_logger);
    setInternalLogger(GSTATE.internal_logger);
    setSignalManager(GSTATE.signal_manager);
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
void globalstateUpdaeAllocationPadding(uint16_t padding)
{
    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        bufferpoolUpdateAllocationPaddings(getWorkerBufferPool(wi), padding, padding);
    }
    GSTATE.flag_buffers_calculated = true;
}

/*!
 * @brief Initializes shortcut pointers for frequently accessed worker-related data.
 *
 * This function initializes shortcut pointers to worker loops, buffer pools, context pools, and pipe tunnel message
 * pools. These shortcuts provide faster access to these resources.
 */
static void initializeShortCuts(void)
{
    assert(GSTATE.flag_initialized);

    static const int kShourtcutsCount = 5;

    const int total_workers = WORKERS_COUNT;

    void **space = (void **) memoryAllocate(sizeof(void *) * kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops                = (wloop_t **) (space + (0ULL * total_workers));
    GSTATE.shortcut_buffer_pools         = (buffer_pool_t **) (space + (1ULL * total_workers));
    GSTATE.shortcut_context_pools        = (generic_pool_t **) (space + (2ULL * total_workers));
    GSTATE.shortcut_pipetunnel_msg_pools = (generic_pool_t **) (space + (3ULL * total_workers));

    for (unsigned int tid = 0; tid < GSTATE.workers_count; tid++)
    {

        GSTATE.shortcut_context_pools[tid]        = WORKERS[tid].context_pool;
        GSTATE.shortcut_pipetunnel_msg_pools[tid] = WORKERS[tid].pipetunnel_msg_pool;
        GSTATE.shortcut_buffer_pools[tid]         = WORKERS[tid].buffer_pool;
        GSTATE.shortcut_loops[tid]                = WORKERS[tid].loop;
    }
}

/*!
 * @brief Initializes master pools for different types of resources.
 *
 * This function initializes master pools for buffer pools (large and small), context pools, and pipe tunnel message
 * pools. Master pools are used for managing the allocation of these resources.
 */
static void initializeMasterPools(void)
{
    assert(GSTATE.flag_initialized);

    GSTATE.masterpool_buffer_pools_large   = masterpoolCreateWithCapacity(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_buffer_pools_small   = masterpoolCreateWithCapacity(2 * ((0) + GSTATE.ram_profile));
    GSTATE.masterpool_context_pools        = masterpoolCreateWithCapacity(2 * ((16) + GSTATE.ram_profile));
    GSTATE.masterpool_pipetunnel_msg_pools = masterpoolCreateWithCapacity(2 * ((8) + GSTATE.ram_profile));
}

/**
 * @brief Signal handler for mainthread exit.
 *
 * Invoked when a termination signal is received and calls mainThreadExitJoin.
 *
 * @param userdata Pointer to the worker structure.
 * @param signum Signal number.
 */
static void exitHandle(void *userdata, int signum)
{
    (void) signum;
    (void) userdata;
    mainThreadExitJoin();
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
    GSTATE.flag_initialized = true;

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
        WORKERS_COUNT      = init_data.workers_count;
        GSTATE.ram_profile = init_data.ram_profile;

        // this check was required to avoid overflow in older version when workers_count was limited to 254
        if (WORKERS_COUNT <= 0 || WORKERS_COUNT > (255))
        {
            LOGW("workers count was not in valid range, value: %u range:[1 - %d]\n", WORKERS_COUNT, (255));
            WORKERS_COUNT = (255);
        }

        WORKERS = (worker_t *) memoryAllocate(sizeof(worker_t) * (WORKERS_COUNT));

        initializeMasterPools();

        for (wid_t i = 0; i < WORKERS_COUNT; ++i)
        {
            workerInit(getWorker(i), i);
        }

        initializeShortCuts();
    }

    // managers
    {
        GSTATE.signal_manager = createSignalManager();
        GSTATE.socekt_manager = socketmanagerCreate();
        GSTATE.node_manager   = nodemanagerCreate();
    }

    // SSL
    {

// later we gona brind openssl anyway...
#if defined(WCRYPTO_BACKEND_OPENSSL)

        opensslGlobalInit();
        GSTATE.flag_openssl_initialized = true;

#endif

#if defined(WCRYPTO_BACKEND_SODIUM)

        GSTATE.flag_libsodium_initialized = initSodium();
        if (! (GSTATE.flag_libsodium_initialized))
        {
            printError("Failed to initialize libsodium\n");
            exit(1);
        }
#endif
    }
    // Spawn all workers except main worker which is current thread
    {
        worker_t *worker      = getWorker(0);
        GSTATE.main_thread_id = getTID();
#ifdef OS_WIN
        worker->thread = (wthread_t) GetCurrentThread();
#else
        worker->thread = pthread_self();
#endif
        registerAtExitCallBack(exitHandle, worker);

        for (unsigned int i = 1; i < WORKERS_COUNT; ++i)
        {
            workerSpawn(&WORKERS[i]);
        }
    }

    startSignalManager();
}

/*!
 * @brief Runs the main thread's event loop.
 *
 * This function runs the event loop for the main worker thread. It asserts that the global state is initialized.
 * After the main loop finishes, it joins all other worker threads and exits.
 */
void runMainThread(void)
{
    assert(GSTATE.flag_initialized);

    workerRun(getWorker(0));
}

/*!
 * @brief Exits the main thread.
 *
 * This function exits the main thread, it is supposed to be called from other threads
 */
WW_EXPORT void mainThreadExitJoin(void)
{
    if ((uint64_t) getTID() ==  GSTATE.main_thread_id)
    {
        return; // incrorrect call, you are in main thread
    }
    workerExitJoin(getWorker(0));
}
