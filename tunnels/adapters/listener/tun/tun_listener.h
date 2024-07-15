#pragma once
#include "api.h"

//                                       /----->    NetworkStack Packet 
// Layer3-packets <------>  TunListener  <------>   NetworkStack Packet 
//                                       \----->    NetworkStack Packet 


tunnel_t         *newTunListener(node_instance_context_t *instance_info);
api_result_t      apiTunListener(tunnel_t *self, const char *msg);
tunnel_t         *destroyTunListener(tunnel_t *self);
tunnel_metadata_t getMetadataTunListener(void);
