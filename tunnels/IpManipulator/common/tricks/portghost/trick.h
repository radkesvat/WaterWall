#pragma once

#include "structure.h"

uint32_t portghosttrickGetTailLength(const ipmanipulator_tstate_t *state);
bool portghosttrickApply(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);
bool portghosttrickRestore(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);
