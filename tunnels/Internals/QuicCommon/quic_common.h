#pragma once

#include "quic_engine.h"
#include "wwapi.h"

typedef struct quic_context quic_context_t;

/* Mappings receive the exact application/carrier line. Calls transfer payload
 * ownership and may synchronously retire either side of the association. */
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
    uint32_t             close_drain_timeout_ms;
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
bool quicConfigureTunnel(tunnel_t *t, const quic_node_settings_t *settings, const quic_output_t *output);

/* Borrow prev's line, create an owned next-side line, publish both associations,
 * and enter a driver scope. NULL refuses startup before next Init. The caller
 * dispatches Init to NextLine with a temporary line reference, then Completes. */
quic_context_t *quicBeginLineInit(tunnel_t *t, line_t *l);
line_t         *quicNextLine(quic_context_t *context);
void            quicCompleteLineInit(quic_context_t *context);

void quicSubmitApplication(tunnel_t *t, line_t *l, sbuf_t *buffer);
void quicSubmitCarrier(tunnel_t *t, line_t *l, sbuf_t *buffer);
/* Immediate application detachment; accepted output drains on the carrier.
 * Carrier Finish instead aborts all work. Only the exact owned next line is
 * destroyed; neither helper reflects Finish toward its caller. */
void quicFinishApplication(tunnel_t *t, line_t *l);
void quicFinishCarrier(tunnel_t *t, line_t *l);
void quicRelayUp(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal);
void quicRelayDown(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal);
void quicSetCarrierPaused(tunnel_t *t, line_t *l, bool paused);

void quicCloseAdmission(tunnel_t *t);
void quicQuiesceWorker(tunnel_t *t, wid_t wid);
void quicStopWorker(tunnel_t *t, wid_t wid);
void quicDestroyState(tunnel_t *t);
