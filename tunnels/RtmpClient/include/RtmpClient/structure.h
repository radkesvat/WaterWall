#pragma once

#include "RtmpClient/interface.h"
#include "rtmp_tunnel.h"

extern const rtmp_output_t rtmpclientOutput;

bool rtmpReadClientUrl(node_t *node, rtmp_settings_t *settings);
