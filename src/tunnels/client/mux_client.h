#pragma once
#include "tunnel.h"
#include "common_types.h"

//
// -----\     /-----
// ------ MUX  -----
// -----/     \-----
//


tunnel_t *newMuxClientTunnel(size_t parallel_lines);
