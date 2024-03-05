#include "ww.h"
#include "hv/hloop.h"
#include "buffer_pool.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "loggers/core_logger.h"

#include "managers/socket_manager.h"
#include "managers/node_manager.h"

size_t threads_count;
hthread_t *threads;
struct hloop_s **loops;
struct buffer_pool_s **buffer_pools;
struct socket_manager_s *socekt_manager;
struct node_manager_s *node_manager;
logger_t *core_logger;
logger_t *network_logger;
logger_t *dns_logger;

struct ww_runtime_state_s
{
    size_t threads_count;
    hthread_t *threads;

    struct hloop_s **loops;
    struct buffer_pool_s **buffer_pools;
    struct socket_manager_s *socekt_manager;
    struct node_manager_s *node_manager;
    logger_t *core_logger;
    logger_t *network_logger;
    logger_t *dns_logger;
};

void setWW(struct ww_runtime_state_s *state)
{

    threads_count = state->threads_count;
    threads = state->threads;
    loops = state->loops;
    buffer_pools = state->buffer_pools;
    socekt_manager = state->socekt_manager;
    node_manager = state->node_manager;
    setCoreLogger(state->core_logger);
    setNetworkLogger(state->network_logger);
    setDnsLogger(state->dns_logger);
    setSocketManager(socekt_manager);
    setNodeManager(node_manager);
    free(state);
}

struct ww_runtime_state_s *getWW()
{
    struct ww_runtime_state_s *state = malloc(sizeof(struct ww_runtime_state_s));
    memset(state, 0, sizeof(struct ww_runtime_state_s));
    state->threads_count = threads_count;
    state->threads = threads;
    state->loops = loops;
    state->buffer_pools = buffer_pools;
    state->socekt_manager = socekt_manager;
    state->node_manager = node_manager;
    state->core_logger = core_logger;
    state->network_logger = network_logger;
    state->dns_logger = dns_logger;
    return state;
}

static HTHREAD_ROUTINE(worker_thread)
{
    hloop_t *loop = (hloop_t *)userdata;
    hloop_run(loop);
    hloop_free(&loop);

    return 0;
}

void createWW(
    char *core_log_file_path,
    char *network_log_file_path,
    char *dns_log_file_path,
    char *core_log_level,
    char *network_log_level,
    char *dns_log_level,
    size_t _threads_count)
{

    core_logger = createCoreLogger(core_log_file_path, core_log_level);
    network_logger = createNetworkLogger(network_log_file_path, network_log_level);
    dns_logger = createDnsLogger(dns_log_file_path, dns_log_level);

    threads_count = _threads_count;
    threads = (hthread_t *)malloc(sizeof(hthread_t) * threads_count);
    
    loops = (hloop_t **)malloc(sizeof(hloop_t *) * threads_count);
    for (int i = 1; i < threads_count; ++i)
    {
        loops[i] = hloop_new(HLOOP_FLAG_AUTO_FREE);
        threads[i] = hthread_create(worker_thread, loops[i]);
    }
    loops[0] = hloop_new(HLOOP_FLAG_AUTO_FREE);
    threads[0] = 0x0;

    buffer_pools = (struct buffer_pool_s **)malloc(sizeof(struct buffer_pool_s *) * threads_count);

    for (int i = 0; i < threads_count; ++i)
    {
        buffer_pools[i] = createBufferPool();
    }

    socekt_manager = createSocketManager();
    node_manager = createNodeManager();
}