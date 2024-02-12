#pragma once
#include "tunnel.h"
#include "common_types.h"

//
// -----\     --------->   /-----
// ------     |0RTT|       -----
// -----/  <---------      \-----
//

// in client mode we only need to add uid header and block the fin packet from
// up side


tunnel_t *newZeroRttClientTunnel();
