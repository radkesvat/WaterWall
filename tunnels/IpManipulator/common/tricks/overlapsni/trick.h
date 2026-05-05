#pragma once

#include "structure.h"

bool overlapsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool overlapsnitrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void overlapsnitrickDestroyState(tunnel_t *t);
