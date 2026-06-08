#pragma once

#include "structure.h"

bool tlsclientRaceIsEnabled(const tlsclient_tstate_t *ts);
bool tlsclientRaceIsMainLine(const tlsclient_lstate_t *ls);
bool tlsclientRaceIsChildLine(const tlsclient_lstate_t *ls);
void tlsclientRaceUpStreamInit(tunnel_t *t, line_t *main_l);
void tlsclientRaceOnChildHandshakeComplete(tunnel_t *t, line_t *child_l);
void tlsclientRaceTimeoutTask(tunnel_t *t, line_t *main_l);
void tlsclientRaceCloseMainLine(tunnel_t *t, line_t *main_l);
void tlsclientRaceCloseMainLineFromUpstream(tunnel_t *t, line_t *main_l);
void tlsclientRaceCloseChildLine(tunnel_t *t, line_t *child_l, bool force_close_main);
void tlsclientRaceCloseChildLineFromDownstream(tunnel_t *t, line_t *child_l, bool force_close_main);
void tlsclientLinestateInitializeRaceMain(tlsclient_lstate_t *ls, uint32_t child_count);
void tlsclientLinestateInitializeRaceChild(tlsclient_lstate_t *ls, line_t *main_l, uint32_t slot,
                                           uint32_t sni_index, const char *selected_sni);
void tlsclientLinestateDestroyRaceMain(tlsclient_lstate_t *ls);
void tlsclientLinestateDestroyRaceChild(tlsclient_lstate_t *ls);
void tlsclientPerformUpStreamInit(tunnel_t *t, line_t *l);
