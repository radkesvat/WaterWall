#pragma once
#include "parser.h"

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

typedef enum hps_phase_e
{
    kHpsRequest,
    kHpsExchange,
    kHpsConnect,
    kHpsRelay,
    kHpsError,
    kHpsClosed
} hps_phase_t;

/* Worker-affine session storage survives re-entrant destruction while a pump/callback holds a reference. */
struct hps_session_s
{
    tunnel_t       *t;
    line_t         *client;
    line_t         *child;
    hps_session_t  *timer_prev;
    hps_session_t  *timer_next;
    wtimer_t       *timer;
    unsigned        references;
    hps_phase_t     phase;
    sbuf_t         *input[2];
    sbuf_t         *output[2];
    hps_body_t      request_body;
    hps_body_t      response_body;
    hps_header_t    trailer_context[2];
    char           *header_storage[2];
    size_t          header_length[2];
    hps_authority_t authority;
    user_handle_t   identity;
    hps_auth_mode_t auth_mode;
    char            credentials[512];
    uint64_t        progress_at;
    uint64_t        header_at[2];
    uint64_t        connect_at;
    unsigned        informationals;
    unsigned        receiving_down;
    bool            pumping;
    bool            again;
    bool            established;
    bool            child_established;
    bool            child_eof;
    bool            paused[2];
    bool            read_paused[2];
    bool            http10;
    bool            head;
    bool            response_header;
    bool            final_committed;
    bool            close_after;
    bool            child_reusable;
    bool            upload_stopped;
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

void hpsInit(tunnel_t *t, line_t *l);
void hpsFinish(tunnel_t *t, line_t *l, bool child);
void hpsPayload(tunnel_t *t, line_t *l, sbuf_t *buf, unsigned direction);
void hpsPressure(tunnel_t *t, line_t *l, unsigned direction, bool paused);
void hpsEstablished(tunnel_t *t, line_t *l);
void hpsCloseChild(hps_session_t *s, bool from_child);
void hpsClose(hps_session_t *s, bool from_client);
void hpsRetain(hps_session_t *s);
void hpsRelease(hps_session_t *s);
void hpsDetachTimer(hps_session_t *s);
