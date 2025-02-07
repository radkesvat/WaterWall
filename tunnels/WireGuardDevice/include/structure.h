#pragma once

#include "wireguard_types.h"
#include "wireguard_endianhelpers.h"
#include "wwapi.h"

// getTickMS
// getRandomBytes
// getTAI64N
// isSystemUnderLoad

typedef struct wgd_tstate_s
{
    wgdevice_init_data_t device_configuration;
    wgpeer_init_data_t  *peers_configuration;
    uint16               peers_configuration_count;

    wireguard_device_t wg_device;
    wireguard_peer_t  *peers;
    uint16             peers_count;

} wgd_tstate_t;

typedef struct wgd_lstate_s
{
    int xxx;
} wgd_lstate_t;

enum
{
    kTunnelStateSize = sizeof(wgd_tstate_t),
    kLineStateSize   = sizeof(wgd_lstate_t)
};

WW_EXPORT void         wireguarddeviceTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *wireguarddeviceTunnelCreate(node_t *node);
WW_EXPORT api_result_t wireguarddeviceTunnelApi(tunnel_t *instance, sbuf_t *message);

WW_EXPORT void wireguarddeviceTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
WW_EXPORT void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
WW_EXPORT void wireguarddeviceTunnelOnPrepair(tunnel_t *t);
WW_EXPORT void wireguarddeviceTunnelOnStart(tunnel_t *t);

WW_EXPORT void wireguarddeviceTunnelUpStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void wireguarddeviceTunnelUpStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamResume(tunnel_t *t, line_t *l);

WW_EXPORT void wireguarddeviceTunnelDownStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void wireguarddeviceTunnelDownStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamResume(tunnel_t *t, line_t *l);

void wireguarddeviceLinestateInitialize(wgd_lstate_t *ls);
void wireguarddeviceLinestateDestroy(wgd_lstate_t *ls);

void wdevCycle(void *arg);
