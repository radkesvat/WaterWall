#pragma once

#include "structure.h"

bool tlsclientParseSniSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t);
bool tlsclientParseSniSelectionSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t);
bool tlsclientParseSniHealthSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t);
void tlsclientFreeSniSettings(tlsclient_tstate_t *ts);
void tlsclientSelectSniForLine(tlsclient_tstate_t *ts, tlsclient_lstate_t *ls, line_t *l);
void tlsclientApplySelectedSniRoute(tlsclient_tstate_t *ts, tlsclient_lstate_t *ls, line_t *l);
uint32_t tlsclientSelectRaceSniIndices(tlsclient_tstate_t *ts, uint32_t *indices, uint32_t max_indices);
void tlsclientRecordSniSuccessForLine(tunnel_t *t, tlsclient_lstate_t *ls);
void tlsclientRecordSniFailureForLine(tunnel_t *t, tlsclient_lstate_t *ls);
void tlsclientReleaseActiveSniLine(tunnel_t *t, tlsclient_lstate_t *ls);
