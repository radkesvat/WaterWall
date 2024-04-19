#pragma once
#include "api.h"

//
// con <------>  PreConnectServer (initiate upstream after we've got some data) <-------> con
//
//

tunnel_t *        newPreConnectServer(node_instance_context_t *instance_info);
api_result_t      apiPreConnectServer(tunnel_t *self, const char *msg);
tunnel_t *        destroyPreConnectServer(tunnel_t *self);
tunnel_metadata_t getMetadataPreConnectServer();
