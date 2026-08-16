#pragma once

#include "socket_manager.h"

tunnel_t *udplistenerShutdownFixtureCreateTunnel(void);

local_idle_item_t *udplistenerShutdownFixtureAttach(tunnel_t *udp, line_t *line, local_idle_table_t *table,
                                                    udpsock_t *socket, hash_t hash);
