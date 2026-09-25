#pragma once
#include "HttpProxyCommon/parser.h"
#include "wwapi.h"

enum
{
    kHpcRequiredPaddingLeft = 10,
    kHpcDeliveryLimit       = 2 * 1024 * 1024,
    kHpcPendingEntries      = 1024
};
typedef enum
{
    kHpcBodyNone,
    kHpcBodyFixed,
    kHpcBodyChunked
} hpc_upload_t;
typedef struct hpc_lstate_s hpc_lstate_t;
typedef struct
{
    hpc_lstate_t *timers;
    bool          quiescing;
} hpc_worker_t;
typedef struct
{
    char                *target, *path, *headers;
    char                 method[8], authorization[685];
    uint64_t             content_length;
    uint32_t             max_header, header_timeout, connect_timeout, idle_timeout;
    uint16_t             port;
    hpc_upload_t         upload;
    bool                 connect, dynamic_address, dynamic_port, verbose;
    wid_t                worker_count;
    hpc_worker_t        *workers;
    bool                 resolve_domains;
    enum domain_strategy domain_strategy;
    tunnel_t            *domain_resolver_tunnel;
    node_t               domain_resolver_node;
    cJSON               *domain_resolver_settings;
} hpc_tstate_t;
struct hpc_lstate_s
{
    tunnel_t                   *t;
    line_t                     *line;
    hpc_lstate_t               *timer_prev, *timer_next;
    wtimer_t                   *timer;
    buffer_budget_t             budgets[2];
    buffer_queue_t              pending[2];
    buffer_budget_reservation_t active_cost;
    sbuf_t                     *request, *suffix, *active;
    char                       *carry, *saved_header;
    size_t                      carry_length;
    hps_header_t                response;
    hps_body_t                  body;
    uint64_t                    upload_remaining, progress_at, header_at, connect_at;
    unsigned                    informational;
    bool                        header_started, status_line_done;
    bool                        next_init, init_busy, header_sent, accepted, est_sent;
    bool                        up_busy, down_busy, next_paused, prev_paused, source_paused;
    bool                        prev_finished, next_finished;
};

WW_EXPORT tunnel_t    *httpproxyclientTunnelCreate(node_t *node);
WW_EXPORT void         httpproxyclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT api_result_t httpproxyclientTunnelApi(tunnel_t *t, sbuf_t *message);
void     httpproxyclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void     httpproxyclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b);
void     httpproxyclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelUpStreamResume(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b);
void     httpproxyclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void     httpproxyclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool     hpcParseSettings(hpc_tstate_t *ts, node_t *node);
void     httpproxyclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
bool     hpcDomainResolverPrepare(tunnel_t *resolver, tunnel_t *owner, line_t *l, void *user_lstate);
bool     hpcBuildRequest(tunnel_t *t, line_t *l);
sbuf_t  *hpcBuffer(line_t *l, size_t n);
uint64_t hpcNow(line_t *l);
bool     hpcAllowed(tunnel_t *t, line_t *l);
void     hpcDetachTimer(hpc_lstate_t *ls);
bool     hpcStartTimer(tunnel_t *t, line_t *l);
void     hpcDestroyState(tunnel_t *t, line_t *l);
void     hpcClose(tunnel_t *t, line_t *l);
bool     hpcPressure(tunnel_t *t, line_t *l);
bool     hpcSendHeader(tunnel_t *t, line_t *l);
bool     hpcDrainUpload(tunnel_t *t, line_t *l);
bool     hpcDrainResponse(tunnel_t *t, line_t *l);
bool     hpcUpload(tunnel_t *t, line_t *l, sbuf_t *b);
bool     hpcResponse(tunnel_t *t, line_t *l, sbuf_t *b);
bool     hpcQueue(tunnel_t *t, line_t *l, sbuf_t *b, unsigned direction);
