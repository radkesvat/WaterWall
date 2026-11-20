#pragma once

#include "objects/node.h"

node_t nodeHintConnectionINGet(void);
node_t nodeHintPacketINGet(void);

/* Returns the startup diagnostic for an input hint, or NULL for other nodes. */
const char *nodeInputHintUnresolvedDiagnostic(const node_t *node);
