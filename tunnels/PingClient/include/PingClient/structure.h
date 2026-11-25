#pragma once

#include "PingCommon/ping_ipv4_node.h"

WW_EXPORT tunnel_t    *pingclientCreate(node_t *node);
WW_EXPORT api_result_t pingclientApi(tunnel_t *instance, sbuf_t *message);
