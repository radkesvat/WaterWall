#pragma once

#include "PingCommon/ping_ipv4_node.h"

WW_EXPORT tunnel_t    *pingserverCreate(node_t *node);
WW_EXPORT api_result_t pingserverApi(tunnel_t *instance, sbuf_t *message);
