#pragma once

#include "basic_types.h"
#include "node.h"

typedef struct tunnel_lib_s
{
    struct tunnel_s *(*creation_proc)(node_instance_context_t *instance_info);
    void (*api_proc)(struct tunnel_s *instance, char *msg);
    struct tunnel_s *(*destroy_proc)(struct tunnel_s *instance);
} tunnel_lib_t;

tunnel_lib_t loadTunnelLib(const char *name);

void registerStaticLib(tunnel_lib_t lib);

