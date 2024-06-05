#include "ww.h"
#include "buffer_pool.h"
#include "generic_pool.h"
#include "hlog.h"
#include "hloop.h"
#include "hplatform.h"
#include "hthread.h"
#include "loggers/core_logger.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "tunnel.h"
#include "utils/stringutils.h"
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

unsigned int             workers_count  = 0;
hthread_t               *workers        = NULL;
unsigned int             frand_seed     = 0;
unsigned int             ram_profile    = 0;
struct hloop_s         **loops          = NULL;
struct buffer_pool_s   **buffer_pools   = NULL;
struct generic_pool_s  **context_pools  = NULL;
struct generic_pool_s  **line_pools     = NULL;
struct socket_manager_s *socekt_manager = NULL;
struct node_manager_s   *node_manager   = NULL;
logger_t                *core_logger    = NULL;
logger_t                *network_logger = NULL;
logger_t                *dns_logger     = NULL;

struct ww_runtime_state_s
{
    unsigned int             workers_count;
    hthread_t               *workers;
    unsigned int             frand_seed;
    unsigned int             ram_profile;
    struct hloop_s         **loops;
    struct buffer_pool_s   **buffer_pools;
    struct generic_pool_s  **context_pools;
    struct generic_pool_s  **line_pools;
    struct socket_manager_s *socekt_manager;
    struct node_manager_s   *node_manager;
    logger_t                *core_logger;
    logger_t                *network_logger;
    logger_t                *dns_logger;
};

void setWW(struct ww_runtime_state_s *state)
{
    workers_count  = state->workers_count;
    workers        = state->workers;
    frand_seed     = state->frand_seed;
    ram_profile    = state->ram_profile;
    loops          = state->loops;
    buffer_pools   = state->buffer_pools;
    context_pools  = state->context_pools;
    line_pools     = state->line_pools;
    socekt_manager = state->socekt_manager;
    node_manager   = state->node_manager;
    setCoreLogger(state->core_logger);
    setNetworkLogger(state->network_logger);
    setDnsLogger(state->dns_logger);
    setSocketManager(socekt_manager);
    setNodeManager(node_manager);
    free(state);
}

struct ww_runtime_state_s *getWW(void)
{
    struct ww_runtime_state_s *state = malloc(sizeof(struct ww_runtime_state_s));
    memset(state, 0, sizeof(struct ww_runtime_state_s));
    state->workers_count  = workers_count;
    state->workers        = workers;
    state->frand_seed     = frand_seed;
    state->ram_profile    = ram_profile;
    state->loops          = loops;
    state->buffer_pools   = buffer_pools;
    state->context_pools  = context_pools;
    state->line_pools     = line_pools;
    state->socekt_manager = socekt_manager;
    state->node_manager   = node_manager;
    state->core_logger    = core_logger;
    state->network_logger = network_logger;
    state->dns_logger     = dns_logger;
    return state;
}

// trimming should not be necessary, using it for test purposes
// todo (remove) should be removed ? (status: disabled)
#ifdef OS_UNIX
void idleFreeMem(htimer_t *timer)
{
    (void) timer;
    malloc_trim(0);
}
#endif

// just because timer is considered "possibly lost" pointer
htimer_t *trim_timer = NULL;

_Noreturn void runMainThread(void)
{

#if defined(OS_UNIX) && false
    trim_timer = htimer_add_period(loops[0], idleFreeMem, 2, 0, 0, 0, 0, INFINITE);
#endif

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

void createWW(const ww_construction_data_t init_data)
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
        network_logger =
            createNetworkLogger(init_data.network_logger_data.log_file_path, init_data.network_logger_data.log_console);
        toUpperCase(init_data.network_logger_data.log_level);
        setNetworkLoggerLevelByStr(init_data.network_logger_data.log_level);

        // libhv has a separate logger,  attach it to the network logger
        logger_set_level_by_str(hv_default_logger(), init_data.network_logger_data.log_level);
        logger_set_handler(hv_default_logger(), getNetworkLoggerHandle());
    }
    if (init_data.dns_logger_data.log_file_path)
    {
        dns_logger = createDnsLogger(init_data.dns_logger_data.log_file_path, init_data.dns_logger_data.log_console);
        toUpperCase(init_data.dns_logger_data.log_level);
        setDnsLoggerLevelByStr(init_data.dns_logger_data.log_level);
    }

    workers_count = init_data.workers_count;
    if (workers_count <= 0 || workers_count > 255)
    {
        fprintf(stderr, "workers count was not in valid range, value: %u range:[1 - 255]\n", workers_count);
    }

    workers       = (hthread_t *) malloc(sizeof(hthread_t) * workers_count);
    frand_seed    = time(NULL);
    ram_profile   = init_data.ram_profile;
    buffer_pools  = (struct buffer_pool_s **) malloc(sizeof(struct buffer_pool_s *) * workers_count);
    context_pools = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) * workers_count);
    line_pools    = (struct generic_pool_s **) malloc(sizeof(struct generic_pool_s *) * workers_count);

    for (unsigned int i = 0; i < workers_count; ++i)
    {
        buffer_pools[i] = createBufferPool();
        context_pools[i] =
            newGenericPoolWithSize((16 * 8) + ram_profile, allocContextPoolHandle, destroyContextPoolHandle);
        line_pools[i] = newGenericPoolWithSize((16 * 4) + ram_profile, allocLinePoolHandle, destroyLinePoolHandle);
    }

    loops      = (hloop_t **) malloc(sizeof(hloop_t *) * workers_count);
    loops[0]   = hloop_new(HLOOP_FLAG_AUTO_FREE, buffer_pools[0]);
    workers[0] = (hthread_t) NULL;

    for (unsigned int i = 1; i < workers_count; ++i)
    {
        loops[i]   = hloop_new(HLOOP_FLAG_AUTO_FREE, buffer_pools[i]);
        workers[i] = hthread_create(worker_thread, loops[i]);
    }

    socekt_manager = createSocketManager();
    node_manager   = createNodeManager();
}
