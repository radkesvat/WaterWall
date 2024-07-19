#include "ww.h"
#include "buffer_pool.h"
#include "generic_pool.h"
#include "hloop.h"
#include "hthread.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "managers/memory_manager.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "pipe_line.h"
#include "tunnel.h"
#include "utils/stringutils.h"

/*
    additional threads that dose not require instances of every pools and they will create what they need
    so, these additions will only reserve their own space on the workers array

    the only purpose of this is to reduce memory usage

    // additional therad 1 : socket manager

*/
enum
{
    kAdditionalReservedWorkers = 1
};

unsigned int                workers_count             = 0;
hthread_t                  *workers                   = NULL;
unsigned int                ram_profile               = 0;
struct hloop_s            **loops                     = NULL;
struct buffer_pool_s      **buffer_pools              = NULL;
struct generic_pool_s     **shift_buffer_pools        = NULL;
struct generic_pool_s     **context_pools             = NULL;
struct generic_pool_s     **line_pools                = NULL;
struct generic_pool_s     **pipeline_msg_pools        = NULL;
struct generic_pool_s     **libhv_hio_pools           = NULL;
struct dedicated_memory_s **dedicated_memory_managers = NULL;
struct dedicated_memory_s    *memory_manager            = NULL;
struct socket_manager_s    *socekt_manager            = NULL;
struct node_manager_s      *node_manager              = NULL;
logger_t                   *core_logger               = NULL;
logger_t                   *network_logger            = NULL;
logger_t                   *dns_logger                = NULL;

struct ww_runtime_state_s
{
    unsigned int                workers_count;
    hthread_t                  *workers;
    unsigned int                ram_profile;
    struct hloop_s            **loops;
    struct buffer_pool_s      **buffer_pools;
    struct generic_pool_s     **shift_buffer_pools;
    struct generic_pool_s     **context_pools;
    struct generic_pool_s     **line_pools;
    struct generic_pool_s     **pipeline_msg_pools;
    struct generic_pool_s     **libhv_hio_pools;
    struct dedicated_memory_s **dedicated_memory_managers;
    struct dedicated_memory_s    *memory_manager;
    struct socket_manager_s    *socekt_manager;
    struct node_manager_s      *node_manager;
    logger_t                   *core_logger;
    logger_t                   *network_logger;
    logger_t                   *dns_logger;
};

void setWW(struct ww_runtime_state_s *state)
{
    workers_count             = state->workers_count;
    workers                   = state->workers;
    ram_profile               = state->ram_profile;
    loops                     = state->loops;
    buffer_pools              = state->buffer_pools;
    shift_buffer_pools        = state->shift_buffer_pools;
    context_pools             = state->context_pools;
    line_pools                = state->line_pools;
    pipeline_msg_pools        = state->pipeline_msg_pools;
    libhv_hio_pools           = state->libhv_hio_pools;
    dedicated_memory_managers = state->dedicated_memory_managers;
    memory_manager            = state->memory_manager;
    socekt_manager            = state->socekt_manager;
    node_manager              = state->node_manager;
    core_logger               = state->core_logger;
    network_logger            = state->network_logger;
    dns_logger                = state->dns_logger;
    setWWMemoryManager(memory_manager);
    setCoreLogger(core_logger);
    setNetworkLogger(network_logger);
    setDnsLogger(dns_logger);
    setSocketManager(socekt_manager);
    setNodeManager(node_manager);
    wwmGlobalFree(state);
}

struct ww_runtime_state_s *getWW(void)
{
    struct ww_runtime_state_s *state = malloc(sizeof(struct ww_runtime_state_s));
    memset(state, 0, sizeof(struct ww_runtime_state_s));
    state->workers_count             = workers_count;
    state->workers                   = workers;
    state->ram_profile               = ram_profile;
    state->loops                     = loops;
    state->buffer_pools              = buffer_pools;
    state->shift_buffer_pools        = shift_buffer_pools;
    state->context_pools             = context_pools;
    state->line_pools                = line_pools;
    state->pipeline_msg_pools        = pipeline_msg_pools;
    state->libhv_hio_pools           = libhv_hio_pools;
    state->dedicated_memory_managers = dedicated_memory_managers;
    state->memory_manager            = memory_manager;
    state->socekt_manager            = socekt_manager;
    state->node_manager              = node_manager;
    state->core_logger               = core_logger;
    state->network_logger            = network_logger;
    state->dns_logger                = dns_logger;
    return state;
}

_Noreturn void runMainThread(void)
{
    hloop_run(loops[0]);
    hloop_free(&loops[0]);
    for (size_t i = 1; i < workers_count; i++)
    {
        hthread_join(workers[i]);
    }
    LOGF("WW: all eventloops exited");
    exit(0);
}

static HTHREAD_ROUTINE(worker_thread) // NOLINT
{
    hloop_t *loop = (hloop_t *) userdata;
    hloop_run(loop);
    hloop_free(&loop);

    return 0;
}

void initHeap(void)
{
    // [Section] custom malloc/free setup (global heap)
    memory_manager = createWWMemoryManager();
}

void createWW(const ww_construction_data_t init_data)
{

    // [Section] loggers
    {
        if (init_data.core_logger_data.log_file_path)
        {
            core_logger =
                createCoreLogger(init_data.core_logger_data.log_file_path, init_data.core_logger_data.log_console);
            toUpperCase(init_data.core_logger_data.log_level);
            setCoreLoggerLevelByStr(init_data.core_logger_data.log_level);
        }
        if (init_data.network_logger_data.log_file_path)
        {
            network_logger = createNetworkLogger(init_data.network_logger_data.log_file_path,
                                                 init_data.network_logger_data.log_console);
            toUpperCase(init_data.network_logger_data.log_level);
            setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

            // libhv has a separate logger,  attach it to the network logger
            logger_set_level_by_str(hv_default_logger(), init_data.network_logger_data.log_level);
            logger_set_handler(hv_default_logger(), getNetworkLoggerHandle());
        }
        if (init_data.dns_logger_data.log_file_path)
        {
            dns_logger =
                createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);
            toUpperCase(init_data.dns_logger_data.log_level);
            setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
        }
    }

    // [Section] workers and pools heap allocation
    {
        workers_count = init_data.workers_count;
        if (workers_count <= 0 || workers_count > (255 - kAdditionalReservedWorkers))
        {
            fprintf(stderr, "workers count was not in valid range, value: %u range:[1 - 255]\n", workers_count);
        }

        workers = (hthread_t *) malloc(sizeof(hthread_t) * (workers_count + kAdditionalReservedWorkers));
        loops   = (hloop_t **) malloc(sizeof(hloop_t *) * (workers_count + kAdditionalReservedWorkers));

        ram_profile = init_data.ram_profile;

        buffer_pools = (struct buffer_pool_s **) malloc(sizeof(struct buffer_pool_s *) *
                                                        (workers_count + kAdditionalReservedWorkers));

        shift_buffer_pools = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) *
                                                               (workers_count + kAdditionalReservedWorkers));
        context_pools      = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) *
                                                               (workers_count + kAdditionalReservedWorkers));
        line_pools         = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) *
                                                               (workers_count + kAdditionalReservedWorkers));
        pipeline_msg_pools = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) *
                                                               (workers_count + kAdditionalReservedWorkers));
        libhv_hio_pools    = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) *
                                                               (workers_count + kAdditionalReservedWorkers));
        dedicated_memory_managers =
            (struct dedicated_memory_s **) malloc(sizeof(struct dedicated_memory_s *) * (workers_count));

        for (unsigned int i = 0; i < workers_count; ++i)
        {
            shift_buffer_pools[i] =
                newGenericPoolWithCap((64) + ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);
            // shift_buffer_pools must be initalized before buffer_pools
            buffer_pools[i] = createBufferPool(i);

            context_pools[i] =
                newGenericPoolWithCap((16) + ram_profile, allocContextPoolHandle, destroyContextPoolHandle);

            line_pools[i] = newGenericPoolWithCap((8) + ram_profile, allocLinePoolHandle, destroyLinePoolHandle);

            pipeline_msg_pools[i] =
                newGenericPoolWithCap((8) + ram_profile, allocPipeLineMsgPoolHandle, destroyPipeLineMsgPoolHandle);

            dedicated_memory_managers[i] = createWWDedicatedMemory();

            // todo (half implemented)
            // libhv_hio_pools[i] =
            //     newGenericPoolWithCap((32) + (2 * ram_profile), allocLinePoolHandle, destroyLinePoolHandle);
        }
    }

    // [Section] initate workers and eventloops
    {
        loops[0]   = hloop_new(HLOOP_FLAG_AUTO_FREE, buffer_pools[0], 0);
        workers[0] = (hthread_t) NULL;
        // all loops must be created here
        for (unsigned int i = 1; i < workers_count; ++i)
        {
            loops[i] = hloop_new(HLOOP_FLAG_AUTO_FREE, buffer_pools[i], (uint8_t) i);
        }

        // additional workers start when they want
        for (unsigned int i = 1; i < workers_count; ++i)
        {
            workers[i] = hthread_create(worker_thread, loops[i]);
        }
    }

    // [Section] setup SocketMangager thread, note that we use smaller buffer pool here
    {
        const uint8_t socketmanager_tid = workers_count; // notice that 0 indexed array
        shift_buffer_pools[socketmanager_tid] =
            newGenericPoolWithCap((64) + ram_profile, allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);
        buffer_pools[socketmanager_tid] = createBufferPool(socketmanager_tid);
        loops[socketmanager_tid] = hloop_new(HLOOP_FLAG_AUTO_FREE, buffer_pools[socketmanager_tid], socketmanager_tid);

        socekt_manager = createSocketManager(loops[socketmanager_tid], socketmanager_tid);
    }

    // [Section] setup NodeManager
    {
        node_manager = createNodeManager();
    }
}
