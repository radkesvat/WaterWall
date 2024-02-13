#pragma once

#include "tunnel.h"

typedef bool (*onAccept)(tunnel_t *self, hio_t *io, uint16_t port, int proto);

void registerSocketAcceptor(hloop_t *loop, tunnel_t *self, uint16_t pmin, uint16_t pmax, char *host, int proto,
                            int multiport_backend, onAccept);

void initSocketDispatcher();

void startSocketDispatcher();
