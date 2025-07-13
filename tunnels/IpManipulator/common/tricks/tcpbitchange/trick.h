#pragma once
#include "structure.h"


void tcpbitchangetrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpbitchangetrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
