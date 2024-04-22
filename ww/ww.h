#pragma once
#include "hv/hthread.h"
#include <stddef.h>

#ifndef NODES_STATIC
#if defined(_MSC_VER)
#define WWEXPORT __declspec(dllexport)
#elif defined(__GNUC__)
#define WWEXPORT __attribute__((visibility("default")))
#else
#define WWEXPORT
#endif
#else
#define WWEXPORT
#endif

struct ww_runtime_state_s;

WWEXPORT void setWW(struct ww_runtime_state_s *state);

struct ww_runtime_state_s *getWW();

typedef struct
{
    char *log_file_path;
    char *log_level;
    bool  log_console;
} logger_construction_data_t;

typedef struct
{
    unsigned int               workers_count;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;
} ww_construction_data_t;

void createWW(ww_construction_data_t data);

_Noreturn void runMainThread();

extern unsigned int             workers_count;
extern hthread_t *              workers;
extern unsigned int             frand_seed;
extern struct hloop_s **        loops;
extern struct buffer_pool_s **  buffer_pools;
extern struct socket_manager_s *socket_disp_state;
extern struct node_manager_s *  node_disp_state;
extern struct logger_s *        core_logger;
extern struct logger_s *        network_logger;
extern struct logger_s *        dns_logger;
