#pragma once
#include "api.h"
#include "shared/trojan/trojan_types.h"

//                                                                        <-- dest2
//                                                <------> udp associate  ---> dest
// meant to be tcp -> tls <------>  TrojanServer
//                                                <------> tcp direct tunnel -> dest
//
//
//
//
//


tunnel_t *newTrojanAuthServer(node_instance_context_t *instance_info);
void apiTrojanAuthServer(tunnel_t *self, char *msg);
tunnel_t *destroyTrojanAuthServer(tunnel_t *self);
