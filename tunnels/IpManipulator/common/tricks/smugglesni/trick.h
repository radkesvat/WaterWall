#pragma once

#include "structure.h"

bool smugglesnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void smugglesnitrickLogDownStreamServerHello(tunnel_t *t, line_t *l, sbuf_t *buf);
void smugglesnitrickDestroyState(tunnel_t *t);
