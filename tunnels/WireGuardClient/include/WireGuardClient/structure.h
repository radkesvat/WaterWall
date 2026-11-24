#pragma once

#include "WireGuardClient/interface.h"
#include "WireGuardCommon/dispatch.h"
#include "WireGuardCommon/engine.h"

typedef enum wireguardclient_carrier_phase_e
{
    kCarrierUnused = 0,
    kCarrierStarting,
    kCarrierOpen,
} wireguardclient_carrier_phase_t;

typedef struct wireguardclient_tstate_s
{
    wireguard_device_t   engine;
    wireguard_dispatch_t dispatch;
    tunnel_t            *tunnel;
    line_t              *carrier; /* Owned normal, worker 0. Inner lines are chain packet lines. */
    uint64_t             carrier_id;
    address_context_t    endpoint;
    wtimer_t            *timer;
    uint32_t             last_attempt;
    bool                 attempted;
    bool                 paused;
    sbuf_t              *pending[128];
    unsigned             pending_head, pending_count;
    size_t               pending_charge;
} wireguardclient_tstate_t;

extern const wireguard_callbacks_t wireguardclientEngineCallbacks;

line_t *wireguardclientEnsureCarrier(wireguardclient_tstate_t *state);
void    wireguardclientFlushPending(wireguardclient_tstate_t *state);
void    wireguardclientDiscardPending(wireguardclient_tstate_t *state);
void    wireguardclientSendInner(tunnel_t *t, sbuf_t *packet, void *argument);
