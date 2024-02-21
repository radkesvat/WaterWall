#pragma once
#include "stddef.h"

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

void createWW(
    char *core_log_file_path,
    char *network_log_file_path,
    char *dns_log_file_path,
    char *core_log_level,
    char *network_log_level,
    char *dns_log_level,
    size_t threads_count);


extern size_t threads;
extern struct hloop_s **loops;
extern struct buffer_pool_s **buffer_pools;
extern struct socket_manager_s *socket_disp_state;
extern struct node_manager_s *node_disp_state;
extern struct logger_s *core_logger;
extern struct logger_s *network_logger;
extern struct logger_s *dns_logger;
