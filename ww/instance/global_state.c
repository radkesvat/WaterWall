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

#if defined(WCRYPTO_BACKEND_OPENSSL)

#include "crypto/openssl_instance.h"

#elif defined(WCRYPTO_BACKEND_SODIUM)

#include "crypto/sodium_instance.h"

#elif defined(WCRYPTO_BACKEND_SOFTWARE)

#else

#error "No crypto backend defined"

#endif

typedef struct worker_msg_s
{
    WorkerMessageCalback callback;
    void                *arg1;
    void                *arg2;
    void                *arg3;
} worker_msg_t;

// Global instance of the ww_global_state_t structure.
ww_global_state_t global_ww_state = {0};

// --- Static helper functions ---

static err_t wwDefaultInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp)
{
    discard inp;
    discard p;
    return 0;
}

static pool_item_t *allocWorkerMessage(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(worker_msg_t));
}

static void destroyWorkerMessage(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

static void initializeMasterPools(void)
{
    GSTATE.masterpool_buffer_pools_large   = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_buffer_pools_small   = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_context_pools        = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_pipetunnel_msg_pools = masterpoolCreateWithCapacity(2 * RAM_PROFILE);
    GSTATE.masterpool_messages             = masterpoolCreateWithCapacity(2 * RAM_PROFILE);

    masterpoolInstallCallBacks(GSTATE.masterpool_messages, allocWorkerMessage, destroyWorkerMessage);
}

static void initializeShortCuts(void)
{
    static const int kShourtcutsCount = 4;

    const uintptr_t total_workers = (uintptr_t) WORKERS_COUNT;

    void **space = (void **) memoryAllocate(sizeof(void *) * (uintptr_t) kShourtcutsCount * total_workers);

    GSTATE.shortcut_loops                = (wloop_t **) (space + (0 * total_workers));
    GSTATE.shortcut_buffer_pools         = (buffer_pool_t **) (space + (1 * total_workers));
    GSTATE.shortcut_context_pools        = (generic_pool_t **) (space + (2 * total_workers));
    GSTATE.shortcut_pipetunnel_msg_pools = (generic_pool_t **) (space + (3 * total_workers));

    for (unsigned int wid = 0; wid < total_workers; wid++)
    {

        GSTATE.shortcut_context_pools[wid]        = WORKERS[wid].context_pool;
        GSTATE.shortcut_pipetunnel_msg_pools[wid] = WORKERS[wid].pipetunnel_msg_pool;
        GSTATE.shortcut_buffer_pools[wid]         = WORKERS[wid].buffer_pool;
        GSTATE.shortcut_loops[wid]                = WORKERS[wid].loop;
    }
}

static void exitHandle(void *userdata, int signum)
{
    discard signum;
    discard userdata;
    atomicStoreExplicit(&GSTATE.application_stopping_flag, true, memory_order_release);


    for (unsigned int wid = 1; wid < WORKERS_COUNT; ++wid)
    {
        workerExitJoin(getWorker(wid));
    }
    workerFinish(getWorker(0));

    finishGlobalState();
}

static void workerMessageReceived(wevent_t *ev)
{
    worker_msg_t *msg = weventGetUserdata(ev);
    wid_t         wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    msg->callback(getWorker(wid), msg->arg1, msg->arg2, msg->arg3);
    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
}

static void tcpipInitDone(void *arg)
{
    discard arg;
    GSTATE.flag_lwip_initialized = 1;
    GSTATE.lwip_process_v4_hook  = wwDefaultInternalLwipIpv4Hook;
    // lwip thread worker id is set to invalid value (larger than workers 0 index)
    tl_wid          = getWorkersCount() - 1; // lwip is the last worker
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
    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
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
    GSTATE = (ww_global_state_t){0};

    GSTATE.flag_initialized = true;
    atomicStoreRelaxed(&GSTATE.application_stopping_flag, false);

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

        for (wid_t i = 0; i < getWorkersCount() - WORKER_ADDITIONS; ++i)
        {
            workerInit(getWorker(i), i, true);
        }

        // WORKER_ADDITIONS 1 : lwip worker dose not have event loop
        workerInit(getWorker(getWorkersCount() - 1), getWorkersCount() - 1, false);

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
            terminateProgram(1);
        }
#endif
    }

    // Spawn all workers except main worker which is current thread
    {
        worker_t *worker      = getWorker(0);
        GSTATE.main_thread_id = (uint64_t) getTID();
#ifdef OS_WIN
        worker->thread = (wthread_t) GetCurrentThread();
#else
        worker->thread = pthread_self();
#endif
        worker->tid = getTID();

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
 * @brief Send a worker message.
 *
 * @param wid The worker ID. (that receives the message)
 * @param cb The callback function.
 * @param arg1 The first argument.
 * @param arg2 The second argument.
 * @param arg3 The third argument.
 */
void sendWorkerMessage(wid_t wid, WorkerMessageCalback cb, void *arg1, void *arg2, void *arg3)
{

    if (getWID() == wid)
    {
        cb(getWorker(wid), arg1, arg2, arg3);
        return;
    }

    assert(wid < getWorkersCount());
    sendWorkerMessageForceQueue(wid, cb, arg1, arg2, arg3);
}

void sendWorkerMessageForceQueue(wid_t wid, WorkerMessageCalback cb, void *arg1, void *arg2, void *arg3)
{
    worker_msg_t *msg;

    assert(wid < getWorkersCount());

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);
    *msg = (worker_msg_t){.callback = cb, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3};
    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(wid);
    ev.cb   = workerMessageReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(wid), &ev);
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

    // if we return right here the main thread exits and program finishes
    // but the thread that requested our exit may still have work to do
    wwSleepMS(2000);
    LOGD("MainThread Returned");

}

/*!
 * @brief destroys global state and ends the program
 *
 */
void finishGlobalState(void)
{
    // its not important which thread called this, at this point only 1 thread is running
    atomicThreadFence(memory_order_seq_cst);
    destroyGlobalState();

    exit(0);
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

WW_EXPORT void destroyGlobalState(void)
{

    memoryFree((void *) GSTATE.shortcut_loops);

    nodemanagerDestroy();
    socketmanagerDestroy();
    signalmanagerDestroy();

    coreloggerDestroy();
    networkloggerDestroy();
    dnsloggerDestroy();
    internaloggerDestroy();
    loggerDestroyDefaultLogger();

    masterpoolDestroy(GSTATE.masterpool_buffer_pools_large);
    masterpoolDestroy(GSTATE.masterpool_buffer_pools_small);
    masterpoolDestroy(GSTATE.masterpool_context_pools);
    masterpoolDestroy(GSTATE.masterpool_pipetunnel_msg_pools);

    // this pool belongs to us and we are rosponsible for making it empty
    masterpoolMakeEmpty(GSTATE.masterpool_messages, NULL);
    masterpoolDestroy(GSTATE.masterpool_messages);

    memoryFree(WORKERS);
    WORKERS = NULL;

    nodelibraryCleanup();
}
