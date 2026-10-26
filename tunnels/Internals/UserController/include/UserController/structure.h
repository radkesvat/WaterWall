#pragma once

#include "AuthenticationClient/interface.h"
#include "interface.h"
#include "wwapi.h"

typedef struct usercontroller_direction_s
{
    traffic_shaper_t shaper;
    tunnel_t        *tunnel;
    line_t          *line;
    uint64_t         ticket;
    bool             upstream;
} usercontroller_direction_t;

// Origin of a line teardown, so the close path never sends a callback back toward the side that
// already finished us (Waterwall directional-finish rule).
typedef enum usercontroller_close_origin_e
{
    kUserControllerCloseInternal = 0, // we decided to close; close both directions
    kUserControllerCloseFromPrev,     // prev/downstream side finished us; close next only
    kUserControllerCloseFromNext      // next/upstream side finished us; close prev only
} usercontroller_close_origin_t;

typedef struct usercontroller_worker_state_s
{
    line_t  **lines;
    size_t    line_count;
    size_t    line_capacity;
    wtimer_t *sweep_timer;
    bool      quiesced;
} usercontroller_worker_state_t;

typedef struct usercontroller_tstate_s
{
    node_t                                *auth_client_node;   // resolved during create
    tunnel_t                              *auth_client_tunnel; // resolved during prepair
    usercontroller_worker_state_t         *worker_states;
    wid_t                                  worker_count;
    uint32_t                               sweep_interval_ms;
    usercontroller_payload_mode_t          fixed_payload_mode;
    bool                                   payload_mode_from_destination;
    usercontroller_payload_mode_resolver_t payload_mode_resolver;
    tunnel_t                              *payload_mode_owner;
    bool                                   prepared;
    atomic_bool                            shaping_stopping;
    bool                                   verbose;
} usercontroller_tstate_t;

typedef struct usercontroller_lstate_s
{
    user_handle_t handle;            // copy of the authenticated user handle (empty when anonymous)
    user_ip_key_t ip_key;            // connecting peer IP, used to release the IP slot on close
    bool          managed;           // true once we reserved a connection slot for this line
    bool          registered;        // true while the worker sweep registry holds a line reference
    bool          started_from_next; // line was initiated from the next side (downstream Init); flips
                                     // the upload/download mapping for traffic accounting
    usercontroller_payload_mode_t payload_mode;
    buffer_budget_t               budget;
    usercontroller_direction_t    directions[2]; // upstream, downstream; user direction is resolved separately
} usercontroller_lstate_t;

enum
{
    kUserControllerDefaultSweepIntervalMs = 1000,
    kTunnelStateSize                      = sizeof(usercontroller_tstate_t),
    kLineStateSize                        = sizeof(usercontroller_lstate_t)
};

WW_EXPORT void         usercontrollerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *usercontrollerTunnelCreate(node_t *node);
WW_EXPORT api_result_t usercontrollerTunnelApi(tunnel_t *instance, sbuf_t *message);

void usercontrollerTunnelOnPrepair(tunnel_t *t);
void usercontrollerTunnelOnStart(tunnel_t *t);
void usercontrollerTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void usercontrollerTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void usercontrollerTunnelUpStreamInit(tunnel_t *t, line_t *l);
void usercontrollerTunnelUpStreamEst(tunnel_t *t, line_t *l);
void usercontrollerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void usercontrollerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void usercontrollerTunnelUpStreamPause(tunnel_t *t, line_t *l);
void usercontrollerTunnelUpStreamResume(tunnel_t *t, line_t *l);

void usercontrollerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void usercontrollerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void usercontrollerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void usercontrollerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void usercontrollerTunnelDownStreamResume(tunnel_t *t, line_t *l);

void usercontrollerLinestateInitialize(usercontroller_lstate_t *ls, bool started_from_next);
void usercontrollerLinestateDestroy(usercontroller_lstate_t *ls);
bool usercontrollerResolvePayloadMode(tunnel_t *t, line_t *l, usercontroller_payload_mode_t *mode);

void usercontrollerTunnelstateDestroy(usercontroller_tstate_t *ts);
void usercontrollerBuildIpKey(line_t *l, user_ip_key_t *out);
bool usercontrollerRegisterLine(tunnel_t *t, line_t *l, usercontroller_lstate_t *ls);
void usercontrollerUnregisterLine(tunnel_t *t, line_t *l, usercontroller_lstate_t *ls);
bool usercontrollerObserveDirectional(tunnel_t *t, usercontroller_lstate_t *ls, uint64_t bytes, bool upstream_payload);
void usercontrollerBandwidthInitialize(tunnel_t *t, line_t *l);
void usercontrollerBandwidthDestroy(usercontroller_lstate_t *ls);
void usercontrollerBandwidthQuiesce(usercontroller_lstate_t *ls);
void usercontrollerBandwidthSubmit(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream);
void usercontrollerBandwidthSetExternalPause(tunnel_t *t, line_t *l, bool upstream, bool paused);
void usercontrollerSweepTimerCallback(wtimer_t *timer);
void usercontrollerCloseLine(tunnel_t *t, line_t *l, usercontroller_close_origin_t origin);
uint64_t    usercontrollerLocalTimeMS(void);
const char *usercontrollerAdmissionReason(user_admission_result_t result);
void        usercontrollerLogAdmissionRejected(tunnel_t *t, line_t *l, const usercontroller_lstate_t *ls,
                                               user_admission_result_t result);
void        usercontrollerLogActiveClose(tunnel_t *t, line_t *l, const usercontroller_lstate_t *ls, const char *reason);
