#pragma once

#include "EnetCommon/endpoint.h"
#include "EnetServer/interface.h"

extern const enet_output_t enetserverOutput;

line_t *enetserverCreateApplication(tunnel_t *t, line_t *carrier);
