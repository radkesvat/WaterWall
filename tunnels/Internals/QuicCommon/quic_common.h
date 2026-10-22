#pragma once

#include "quic_engine.h"
#include "wwapi.h"

typedef struct quic_context quic_context_t;

/* Node-owned mappings, invoked only after the QUICHE call returns. Payload
 * callbacks take buffer ownership and every callback may retire the line. */
typedef struct quic_output
{
    TunnelFlowRoutinePayload wire_payload;
    TunnelFlowRoutinePayload application_payload;
    TunnelFlowRoutinePause   application_pause;
    TunnelFlowRoutineResume  application_resume;
} quic_output_t;

typedef struct quic_tstate
{
    ww_quic_config_t    *config;
    quic_context_t     **workers;
    const quic_output_t *output;
    uint32_t             max_bytes;
    uint32_t             max_buffers;
    bool                 client;
    bool                 stream_carrier;
    bool                 verbose;
    atomic_bool          stopping;
} quic_tstate_t;

typedef struct quic_lstate
{
    quic_context_t *context;
} quic_lstate_t;

typedef struct quic_node_settings
{
    ww_quic_settings_t engine;
    bool               stream_carrier;
    bool               verbose;
} quic_node_settings_t;

bool quicReadCommonSettings(const node_t *node, quic_node_settings_t *settings);
bool quicReadString(const cJSON *json, const char *name, const char **value, bool required);
bool quicReadBoolean(const cJSON *json, const char *name, bool *value);
/* Initializes shared state in an already allocated tunnel. Failure leaves no
 * shared resources to destroy. The immutable output mapping outlives the tunnel. */
bool quicConfigureTunnel(tunnel_t *t, const quic_node_settings_t *settings, const quic_output_t *output);

/* Initializes the borrowed line and enters its driver scope. NULL means startup
 * admission is closed; the caller finishes toward prev. On success next Init is
 * admitted: dispatch it immediately, then Complete exactly once, even if the
 * callback retired the line. The context holds its allocation and line reference. */
quic_context_t *quicBeginLineInit(tunnel_t *t, line_t *l);
void            quicCompleteLineInit(quic_context_t *context);

/* Transfer the whole buffer on every path; serialize nested input behind the
 * active driver. Node callbacks explicitly select their application's/carrier's side. */
void quicSubmitApplication(tunnel_t *t, line_t *l, sbuf_t *buffer);
void quicSubmitCarrier(tunnel_t *t, line_t *l, sbuf_t *buffer);
bool quicCanRelay(tunnel_t *t, line_t *l);

typedef enum quic_finish_side
{
    kQuicFinishFromPrev,
    kQuicFinishFromNext
} quic_finish_side_t;

typedef enum quic_finish_mode
{
    kQuicFinishFlushApplication,
    kQuicFinishDiscardCarrier
} quic_finish_mode_t;

typedef struct quic_finish_scope
{
    quic_context_t *context;
    bool            entered;
    bool            forward;
} quic_finish_scope_t;

/* Marks the sender closed before any final output and detaches local state.
 * If forward is true, the node forwards Finish only away from the sender.
 * Always End exactly once afterward; do not access lstate after Begin. Driver
 * references and deferred destruction remain valid through nested Finish. */
quic_finish_scope_t quicBeginFinish(tunnel_t *t, line_t *l, quic_finish_side_t sender, quic_finish_mode_t mode);
void                quicEndFinish(quic_finish_scope_t *scope);

void quicCloseAdmission(tunnel_t *t);
void quicQuiesceWorker(tunnel_t *t, wid_t wid);
/* Validates the borrowed registry and releases shared state; caller then destroys
 * the tunnel. No line is owned or destroyed by QuicCommon. */
void quicDestroyState(tunnel_t *t);
