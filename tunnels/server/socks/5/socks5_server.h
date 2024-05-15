#pragma once
#include "api.h"

//                                           <------>   udp associate   <---> dest
//    con      <------>  Socks5 Server
//                                           <------> tcp direct tunnel <---> dest

tunnel_t *        newSocks5Server(node_instance_context_t *instance_info);
api_result_t      apiSocks5Server(tunnel_t *self, const char *msg);
tunnel_t *        destroySocks5Server(tunnel_t *self);
tunnel_metadata_t getMetadataSocks5Server(void);
