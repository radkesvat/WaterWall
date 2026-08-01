#pragma once

#include "structure.h"

bool smugglesnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void smugglesnitrickLogDownStreamServerHello(tunnel_t *t, line_t *l, sbuf_t *buf);
bool smugglesnitrickInitializeState(tunnel_t *t);
void smugglesnitrickDestroyState(tunnel_t *t);
