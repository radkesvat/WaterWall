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

/* Parsed trailer names borrow the original header owned by this optional object. */
typedef struct hps_trailer_owner_s
{
    hps_header_t context;
    char        *storage;
    size_t       length;
} hps_trailer_owner_t;

/* Directional data bookkeeping, embedded in the worker-affine session. No independent lifetime. */
typedef struct hps_direction_state_s
{
    /* All retained/active buffer slots are ordinary; splice is settled at admission. */
    sbuf_t *input;
    sbuf_t *output;
    sbuf_t *deferred; /* One bounded already-delivered remainder. */
    sbuf_t *incoming; /* Active Payload remainder; nested input appends here in FIFO order. */

    hps_body_t           body;
    hps_trailer_owner_t *trailer; /* Present only while an actual chunked body needs context. */
    uint64_t             header_at;
    unsigned             receiving;
    bool                 paused : 1;
    bool                 read_paused : 1;

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
