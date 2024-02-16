#pragma once
#include "tunnel.h"
#include "common_types.h"
#include "cJSON.h"
//
// user <-----\               /----->    con 1
// user <------>  TcpListener  <------>  con 2
// user <-----/               \----->    con 3
//

tunnel_t *newTcpListener(hloop_t **loop, cJSON *settings);
