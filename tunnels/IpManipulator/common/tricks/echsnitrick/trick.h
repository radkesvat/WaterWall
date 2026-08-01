#pragma once

#include "structure.h"

bool echsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool echsnitrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool echsnitrickInitializeState(tunnel_t *t);
void echsnitrickDestroyState(tunnel_t *t);
