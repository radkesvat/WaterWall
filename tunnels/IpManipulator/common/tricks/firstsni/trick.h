#pragma once

#include "structure.h"

bool firstsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool firstsnitrickInitializeState(tunnel_t *t);
void firstsnitrickDestroyState(tunnel_t *t);
