#pragma once
#include "tunnel.h"
#include "basic_types.h"

//
// -----\     /-----
// ------ MUX  -----
// -----/     \-----
//


tunnel_t *newMuxClientTunnel(size_t parallel_lines);
