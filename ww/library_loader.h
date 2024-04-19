#pragma once

#include "basic_types.h"
#include "node.h"
#include "utils/hashutils.h"

typedef struct tunnel_lib_s
{
    hash_t hash_name;
    struct tunnel_s *(*creation_proc)(node_instance_context_t *instance_info);
    api_result_t (*api_proc)(struct tunnel_s *instance, char *msg);
    struct tunnel_s *(*destroy_proc)(struct tunnel_s *instance);
    tunnel_metadata_t (*getmetadata_proc)();

} tunnel_lib_t;

tunnel_lib_t loadTunnelLib(const char *name);
tunnel_lib_t loadTunnelLibByHash(hash_t hname);
void         registerStaticLib(tunnel_lib_t lib);
