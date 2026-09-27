#pragma once
#include "interface.h"
#include "structure.h"

/* Small shared state accessors; callers own session/line lifetime. */
static inline uint64_t hpsNowMs(const hps_session_t *s)
{
    return wloopNowMonotonicMS(getWorkerLoop(lineGetWID(s->client)));
}

static inline hps_tstate_t *hpsSettings(hps_session_t *s)
{
    return tunnelGetState(s->t);
}

static inline bool hpsIsActive(hps_session_t *s)
{
    return s->phase != kHpsClosed && lineIsAlive(s->client);
}

void hpsRetain(hps_session_t *s);
void hpsRelease(hps_session_t *s);
void hpsDetachTimer(hps_session_t *s);
void hpsCloseChild(hps_session_t *s, bool from_child);
void hpsClose(hps_session_t *s, bool from_client);
void hpsClearLineState(line_t *l, tunnel_t *t);
void hpsCreateChild(hps_session_t *s, const char *username, const char *password);
void hpsDiscardBuffer(hps_session_t *s, sbuf_t **slot);
void hpsClearHeader(hps_session_t *s, hps_direction_t d);
/* Success transfers storage; refusal leaves it with the caller. */
bool   hpsRetainTrailer(hps_session_t *s, hps_direction_t d, const hps_header_t *header, char *storage, size_t length);
size_t hpsPendingBytes(hps_session_t *s);
bool   hpsAppendInput(hps_session_t *s, hps_direction_t direction, const unsigned char *data, size_t n);
bool   hpsQueueOutput(hps_session_t *s, hps_direction_t d, const char *data, size_t n);
void   hpsFail(hps_session_t *s, unsigned status);
void   hpsUpdatePressure(hps_session_t *s);
bool   hpsDeliverPayload(hps_session_t *s, hps_direction_t d, sbuf_t *b);
int    hpsReadHeader(hps_session_t *s, hps_direction_t d, char **block);
bool   hpsRewriteHeaderOutput(hps_session_t *s, const hps_header_t *h, hps_direction_t d);
hps_step_t hpsProcessBody(hps_session_t *s, hps_direction_t d);
void       hpsPump(hps_session_t *s);
bool       hpsProcessRequest(hps_session_t *s);
bool       hpsProcessResponse(hps_session_t *s);
void       hpsAcceptPayload(hps_session_t *s, line_t *l, sbuf_t *buf, hps_direction_t direction);

/* Evaluation only: the request orchestrator owns commitment and branch selection. */
typedef enum hps_auth_result_e
{
    kHpsAuthAccepted,
    kHpsAuthDenied,
    kHpsAuthUnavailable,
    kHpsAuthInternalFailure
} hps_auth_result_t;

bool              hpsParseSettings(hps_tstate_t *ts, node_t *node);
hps_auth_result_t hpsEvaluateAuth(const hps_tstate_t *ts, const char *credentials, char username[256],
                                  char password[256], char key[512], user_handle_t *identity);
