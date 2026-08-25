#pragma once

#include "UdpListener/interface.h"
#include "wwapi.h"

WW_EXPORT node_t                         nodeTcpUdpListenerGet(void);
WW_EXPORT udplistener_dynamic_provider_t tcpudplistenerGetDynamicProvider(tunnel_t *t);
