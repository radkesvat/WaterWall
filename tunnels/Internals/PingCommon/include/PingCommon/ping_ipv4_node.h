#pragma once

#include "PingCommon/ping_ipv4.h"

bool      pingipv4ReadSettings(const node_t *node, ping_ipv4_config_t *config);
tunnel_t *pingipv4NodeCreate(node_t *node, ping_ipv4_role_t role);
