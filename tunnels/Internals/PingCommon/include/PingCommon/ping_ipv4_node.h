#pragma once

#include "PingCommon/ping_ipv4.h"

typedef struct ping_ipv4_settings_s
{
    ping_ipv4_config_t wire;
    uint16_t           sequence_start;
    bool               sequence_enabled;
    bool               random_identifier;
    bool               send_replies;
} ping_ipv4_settings_t;

bool      pingipv4ReadSettings(const node_t *node, ping_ipv4_settings_t *config);
tunnel_t *pingipv4NodeCreate(node_t *node, ping_ipv4_role_t role);
