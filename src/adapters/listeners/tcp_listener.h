#pragma once
#include "tunnel.h"
#include "common_types.h"
//
// user <-----\               /----->
// user <------>  TcpListener  <------>
// user <-----/               \----->
//

tunnel_t *newTcpListener(hloop_t *loop, char *host, int port);
void startTcpListener(tunnel_t *self);