#pragma once

#include "structure.h"

bool synfinsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool synfinsnitrickInitializeState(tunnel_t *t);
void synfinsnitrickDestroyState(tunnel_t *t);
