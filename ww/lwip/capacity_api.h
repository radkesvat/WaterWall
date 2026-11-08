#pragma once

#include "api/node_api.h"

/* Register the read-only process-wide stack-stats operation during startup. */
bool wwLwipCapacityRegisterApi(tunnel_t *tunnel);
