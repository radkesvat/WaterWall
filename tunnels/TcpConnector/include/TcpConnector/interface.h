#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodeTcpConnectorGet(void);
WW_EXPORT tunnel_t *tcpconnectorTunnelGetEntryTunnel(tunnel_t *t);

/* The composite owns the provider; this connector retains its preparation helper. */
WW_EXPORT void tcpconnectorTunnelSetDnsProvider(tunnel_t *t, tunnel_t *provider);
