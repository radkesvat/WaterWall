#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodeUdpConnectorGet(void);
WW_EXPORT tunnel_t *udpconnectorTunnelGetEntryTunnel(tunnel_t *t);

/* The composite owns the provider; this connector retains its preparation helper. */
WW_EXPORT void udpconnectorTunnelSetDnsProvider(tunnel_t *t, tunnel_t *provider);
