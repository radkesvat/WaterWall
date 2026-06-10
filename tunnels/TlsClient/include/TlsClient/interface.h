#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodeTlsClientGet(void);
WW_EXPORT tunnel_t *tlsclientTunnelCreate(node_t *node);
WW_EXPORT void   tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
WW_EXPORT bool   tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool   tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
