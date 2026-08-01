#pragma once
#include "structure.h"

void tcpbitchangetrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t **buf);
void tcpbitchangetrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t **buf);

/*
 * Direction-specific action queries. trick_tcp_bit_changes combines both
 * directions, so configuration compatibility rules that only concern the
 * upstream (flow-opening and ClientHello) path must ask these instead.
 */
bool tcpbitchangetrickHasUpstreamActions(const ipmanipulator_tstate_t *state);
bool tcpbitchangetrickHasDownstreamActions(const ipmanipulator_tstate_t *state);
