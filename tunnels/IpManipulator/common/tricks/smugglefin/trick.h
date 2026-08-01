#pragma once

#include "structure.h"

bool smugglefintrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool smugglefintrickInitializeState(tunnel_t *t);
void smugglefintrickDestroyState(tunnel_t *t);
