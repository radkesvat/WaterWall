#pragma once

#include "wwapi.h"

WW_EXPORT node_t       nodeStreamFragmenterGet(void);
WW_EXPORT tunnel_t    *streamfragmenterTunnelCreate(node_t *node);
WW_EXPORT api_result_t streamfragmenterTunnelApi(tunnel_t *instance, sbuf_t *message);
