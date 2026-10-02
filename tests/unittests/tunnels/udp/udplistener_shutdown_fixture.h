/*
 * Covers: udplistener shutdown fixture; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and
 * cleanup; this header has no independent CTest entry.
 * CTest: Shared header; see the including suite for execution.
 */
#pragma once

#include "socket_manager.h"

tunnel_t *udplistenerShutdownFixtureCreateTunnel(void);

local_idle_item_t *udplistenerShutdownFixtureAttach(tunnel_t *udp, line_t *line, local_idle_table_t *table,
                                                    udpsock_t *socket, hash_t hash);
