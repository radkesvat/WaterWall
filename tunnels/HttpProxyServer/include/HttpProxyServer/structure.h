#pragma once
#include "parser.h"

/* Fixed per-direction allowance for already-delivered input, independent of pool sizing. */
enum
{
    kHpsDeliveryHeadroomBytes = 2U * 1024U * 1024U
};

typedef struct hps_session_s hps_session_t;
typedef struct hps_lstate_s  hps_lstate_t;

typedef enum hps_auth_mode_e
{
    kHpsAuthNone,
    kHpsAuthLocal,
    kHpsAuthTracked
} hps_auth_mode_t;

typedef struct hps_local_user_s
{
    char username[256];
    char password[256];
} hps_local_user_t;

typedef struct hps_worker_s
{
    hps_lstate_t  *children;
    hps_session_t *timers;
    bool           quiescing;
} hps_worker_t;

typedef struct hps_tstate_s
{
    node_t           *fallback_node;
    tunnel_t         *fallback;
    node_t           *auth_node;
    tunnel_t         *auth;
    node_t            controller_node;
    tunnel_t         *controller;
    hps_worker_t     *workers;
    unsigned          worker_count;
    uint32_t          max_header;
    uint32_t          max_pending;
    uint32_t          header_timeout;
    uint32_t          connect_timeout;
    uint32_t          idle_timeout;
    hps_auth_mode_t   auth_mode;
    hps_local_user_t *users;
    size_t            user_count;
    bool              verbose;
} hps_tstate_t;

struct hps_lstate_s
{
    hps_session_t *session;
    line_t        *line;
    hps_lstate_t  *prev;
    hps_lstate_t  *next;
    bool           child;
};

typedef enum hps_direction_e
{
    kHpsUpstream,
    kHpsDownstream
} hps_direction_t;

typedef enum hps_step_e
{
    kHpsStepBlocked,
    kHpsStepNeedInput,
    kHpsStepProgress,
    kHpsStepDone
} hps_step_t;

typedef enum hps_phase_e
{
    kHpsRequest,
    kHpsExchange,
    kHpsConnect,
    kHpsRelay,
    kHpsFallback,
    kHpsError,
    kHpsClosed
} hps_phase_t;

/* Directional data bookkeeping, embedded in the worker-affine session. No independent lifetime. */
typedef struct hps_direction_state_s
{
    /* All retained/active buffer slots are ordinary; splice is settled at admission. */
    sbuf_t *input;
    sbuf_t *output;
    sbuf_t *deferred; /* One bounded already-delivered remainder. */
    sbuf_t *incoming; /* Active Payload remainder; nested input appends here in FIFO order. */

    hps_body_t body;
    char      *header_storage; /* Owns the copied header borrowed by trailer_context. */
    size_t     header_length;
    uint64_t   header_at;
    unsigned   receiving;
    bool       paused : 1;
    bool       read_paused : 1;

    hps_header_t trailer_context;
} hps_direction_state_t;

/* Worker-affine session storage survives re-entrant destruction while a pump/callback holds a reference. */
struct hps_session_s
{
    tunnel_t             *t;
    line_t               *client;
    line_t               *child;
    tunnel_t             *child_entry;
    hps_session_t        *timer_prev;
    hps_session_t        *timer_next;
    wtimer_t             *timer;
    unsigned              references;
    hps_phase_t           phase;
    hps_direction_state_t directions[2];
    hps_authority_t       authority;
    user_handle_t         identity;
    hps_auth_mode_t       auth_mode;
    char                  credentials[512];
    uint64_t              progress_at;
    uint64_t              connect_at;
    unsigned              informationals;
    bool                  protected_committed : 1;
    bool                  child_initializing : 1;
    bool                  pumping : 1;
    bool                  again : 1;
    bool                  established : 1;
    bool                  child_established : 1;
    bool                  child_eof : 1;
    bool                  http10 : 1;
    bool                  head : 1;
    bool                  response_header : 1;
    bool                  final_committed : 1;
    bool                  close_after : 1;
    bool                  child_reusable : 1;
    bool                  upload_stopped : 1;
};

WW_EXPORT tunnel_t    *httpproxyserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpproxyserverTunnelApi(tunnel_t *t, sbuf_t *message);
void                   httpproxyserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void                   httpproxyserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void                   httpproxyserverTunnelOnPrepair(tunnel_t *t);
void httpproxyserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void httpproxyserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void httpproxyserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpproxyserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamResume(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpproxyserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

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

void       hpsRetain(hps_session_t *s);
void       hpsRelease(hps_session_t *s);
void       hpsDetachTimer(hps_session_t *s);
void       hpsCloseChild(hps_session_t *s, bool from_child);
void       hpsClose(hps_session_t *s, bool from_client);
void       hpsClearLineState(line_t *l, tunnel_t *t);
void       hpsCreateChild(hps_session_t *s, const char *username, const char *password);
void       hpsDiscardBuffer(hps_session_t *s, sbuf_t **slot);
void       hpsClearHeader(hps_session_t *s, hps_direction_t d);
size_t     hpsPendingBytes(hps_session_t *s);
bool       hpsAppendInput(hps_session_t *s, hps_direction_t direction, const unsigned char *data, size_t n);
bool       hpsQueueOutput(hps_session_t *s, hps_direction_t d, const char *data, size_t n);
void       hpsFail(hps_session_t *s, unsigned status);
void       hpsUpdatePressure(hps_session_t *s);
bool       hpsDeliverPayload(hps_session_t *s, hps_direction_t d, sbuf_t *b);
int        hpsReadHeader(hps_session_t *s, hps_direction_t d, char **block);
bool       hpsRewriteHeaderOutput(hps_session_t *s, const hps_header_t *h, hps_direction_t d);
hps_step_t hpsProcessBody(hps_session_t *s, hps_direction_t d);
void       hpsPump(hps_session_t *s);
bool       hpsProcessRequest(hps_session_t *s);
bool       hpsProcessResponse(hps_session_t *s);
void       hpsAcceptPayload(hps_session_t *s, line_t *l, sbuf_t *buf, hps_direction_t direction);
