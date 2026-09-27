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
    bool                        header_started : 1;
    bool                        status_line_done : 1;
    bool                        next_init : 1;
    bool                        init_busy : 1;
    bool                        header_sent : 1;
    bool                        accepted : 1;
    bool                        est_sent : 1;
    bool                        up_busy : 1;
    bool                        down_busy : 1;
    bool                        next_paused : 1;
    bool                        prev_paused : 1;
    bool                        source_paused : 1;
    bool                        prev_finished : 1;
    bool                        next_finished : 1;
};
