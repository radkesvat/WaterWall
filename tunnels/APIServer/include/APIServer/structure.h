#pragma once

#include "APIServer/codec.h"
#include "APIServer/interface.h"
#include "api/dispatcher.h"

enum
{
    kApiTurnBytes                = 64 * 1024,
    kApiTurnFrames               = 4,
    kApiMinimumResultAllowance   = 4096,
    kApiHandlerMetadataAllowance = 8192
};

typedef struct api_permission_s
{
    struct api_permission_s    *next;
    char                       *config;
    char                       *node;
    char                       *operation;
    tunnel_t                   *target;
    const node_api_operation_t *descriptor;
} api_permission_t;

typedef struct api_client_s
{
    struct api_client_s *next;
    char                *name;
    uint8_t              token[32];
    api_permission_t    *permissions;
} api_client_t;

typedef struct api_limits_s
{
    size_t   max_request_envelope;
    size_t   max_response_envelope;
    size_t   max_input_bytes;
    size_t   max_line_memory;
    size_t   max_input_fragments;
    size_t   max_queued_requests;
    size_t   max_sessions;
    size_t   max_jobs;
    size_t   handler_working_memory;
    size_t   max_memory;
    uint32_t frame_timeout_ms;
    uint32_t request_timeout_ms;
    uint32_t output_timeout_ms;
    uint32_t idle_timeout_ms;
} api_limits_t;

typedef struct api_input_s
{
    struct api_input_s *next;
    sbuf_t             *buffer;
    size_t              charge;
    uint64_t            received_ms;
} api_input_t;

typedef struct apiserver_lstate_s
{
    struct apiserver_lstate_s  *next;
    struct apiserver_lstate_s **previous;
    tunnel_t                   *tunnel;
    line_t                     *line;
    wtimer_t                   *timer;
    buffer_budget_t             budget;
    uint64_t                    session_token;
    uint64_t                    request_token;
    uint64_t                    frame_deadline;
    uint64_t                    output_deadline;
    uint64_t                    idle_deadline;
    api_input_t                *input_head;
    api_input_t                *input_tail;
    size_t                      input_bytes;
    size_t                      input_fragments;
    uint8_t                     header[4];
    size_t                      header_size;
    char                       *frame;
    size_t                      frame_size;
    size_t                      frame_used;
    api_request_t              *requests;
    api_request_t              *requests_tail;
    size_t                      request_count;
    node_api_job_t             *job;
    uint8_t                    *output;
    size_t                      output_size;
    size_t                      output_offset;
    bool                        output_paused : 1;
    bool                        input_paused : 1;
    bool                        processing : 1;
    bool                        close_after_output : 1;
    bool                        quiesced : 1;
} apiserver_lstate_t;

typedef struct apiserver_tstate_s
{
    api_limits_t         limits;
    api_client_t        *clients;
    node_api_domain_t   *domain;
    apiserver_lstate_t **sessions;
    atomic_uint          session_count;
    atomic_ullong        serial;
    atomic_bool          stopping;
} apiserver_tstate_t;

bool        apiserverLoadSettings(apiserver_tstate_t *ts, const cJSON *settings);
void        apiserverFreeSettings(apiserver_tstate_t *ts);
const char *apiserverAuthorize(apiserver_tstate_t *ts, api_request_t *request, tunnel_t **target,
                               const node_api_operation_t **operation);

/* Owner-worker session storage. Failed initialization leaves no reservation or
 * registry entry; the Init callback must notify the source owner of rejection. */
bool     apiserverLinestateInitialize(tunnel_t *t, line_t *line);
void     apiserverLinestateDestroy(apiserver_lstate_t *ls);
bool     apiserverReserve(apiserver_lstate_t *ls, size_t charge);
void     apiserverRelease(apiserver_lstate_t *ls, size_t charge);
void     apiserverAbandonJob(apiserver_lstate_t *ls);
uint64_t apiserverNextToken(apiserver_tstate_t *ts);

/* Input owns retained buffers and the complete-request FIFO. */
bool apiserverParseInput(apiserver_lstate_t *ls);
bool apiserverFramingError(apiserver_lstate_t *ls, const char *error);
void apiserverReleaseRequest(apiserver_lstate_t *ls);

/* Publish one framed response without invoking a neighboring tunnel. */
bool apiserverPublishResponse(apiserver_lstate_t *ls, const char *error, const node_api_operation_t *op,
                              enum api_result_e code, const uint8_t *body, size_t body_size);

/* Progress and local close may finish the borrowed line through its source owner.
 * The caller must not subsequently access it without its own lifetime proof. */
void apiserverProgress(tunnel_t *t, line_t *line);
void apiserverCloseSession(tunnel_t *t, line_t *line);
bool apiserverArmTimer(apiserver_lstate_t *ls);
void apiserverComplete(void *context, uint64_t session, uint64_t request, const node_api_reply_t *reply);
