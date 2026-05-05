#pragma once

#include "structure.h"

bool smugglefintrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void smugglefintrickDestroyState(tunnel_t *t);
