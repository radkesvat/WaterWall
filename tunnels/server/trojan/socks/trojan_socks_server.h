#pragma once
#include "api.h"
#include "shared/trojan/trojan_types.h"

//
//                                           <------>   udp associate   <---> dest(s)
//    con      <------>  TrojanSocksServer
//                                           <------> tcp direct tunnel <---> dest
//
//
//
// * in the regular standard trojan, con is defined as  tcp->tls( with fallback ) + userauth(with fallback)
//
//

tunnel_t *newTrojanSocksServer(node_instance_context_t *instance_info);
api_result_t apiTrojanSocksServer(tunnel_t *self, char *msg);
tunnel_t *destroyTrojanSocksServer(tunnel_t *self);
tunnel_metadata_t getMetadataTrojanSocksServer();