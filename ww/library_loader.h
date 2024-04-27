#pragma once

#include "basic_types.h"
#include "node.h"
#include "utils/hashutils.h"

/*

    Load librarys form any source, most probably its a static library
    otherwise, there should be a .dll , .so lib which is supposed to be loaded
    in a cross platform way.

    this is a general interface for loading librarys that implement tunnel interface
*/

typedef struct tunnel_lib_s
{
    struct tunnel_s *(*createHandle)(node_instance_context_t *instance_info);
    struct tunnel_s *(*destroyHandle)(struct tunnel_s *instance);
    api_result_t (*apiHandle)(struct tunnel_s *instance, const char *msg);
    tunnel_metadata_t (*getMetadataHandle)();
    hash_t hash_name;

} tunnel_lib_t;

tunnel_lib_t loadTunnelLib(const char *name);
tunnel_lib_t loadTunnelLibByHash(hash_t hname);
void         registerStaticLib(tunnel_lib_t lib);
