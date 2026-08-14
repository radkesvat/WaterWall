#pragma once

#include "wwapi.h"

#ifndef LOG_PACKET_INFO
#define LOG_PACKET_INFO 0
#endif
#ifndef LOG_SSDP
#define LOG_SSDP 0
#endif
#ifndef LOG_MDNS
#define LOG_MDNS 0
#endif
#ifndef LOG_V6
#define LOG_V6 0
#endif

typedef struct tundevice_tstate_s
{
    packet_lifecycle_anchor_t lifecycle_anchor;

    // settings form json
    char    *name;        // name of the device
    char    *ip_subnet;   // ip/subnet
    char    *ip_present;  //  only ip
    int      subnet_mask; // only subnet mask
    uint16_t mtu;         // device mtu, default is GLOBAL_MTU_SIZE

    bool   system_route_enabled;
    char  *route_table;
    char **system_routes;
    size_t system_route_count;
    size_t system_routes_installed;
    char  *post_up_script;
    char  *pre_down_script;

    char  *dns_servers[kTunDeviceMaxDnsServers];
    size_t dns_server_count;
    bool   dns_servers_installed;

    bool loop_protection_enabled; // exclude this process's own traffic from the TUN
    bool egress_pin_published;    // this instance contributed a reference to the global egress pin

    tun_device_t *tdev;

} tundevice_tstate_t;

_Static_assert(offsetof(tundevice_tstate_t, lifecycle_anchor) == 0,
               "TunDevice lifecycle anchor must remain the tunnel-state prefix");

enum
{
    kTunnelStateSize = sizeof(tundevice_tstate_t)
};

WW_EXPORT void         tundeviceTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tundeviceTunnelCreate(node_t *node);
WW_EXPORT api_result_t tundeviceTunnelApi(tunnel_t *instance, sbuf_t *message);

void tundeviceTunnelOnStart(tunnel_t *t);
void tundeviceTunnelOnStop(tunnel_t *t);

bool tundeviceLoadRouteSettings(tundevice_tstate_t *state, const cJSON *settings);
bool tundeviceApplySystemRoutes(tundevice_tstate_t *state);
void tundeviceCleanupSystemRoutes(tundevice_tstate_t *state);
void tundeviceFreeRouteSettings(tundevice_tstate_t *state);

bool tundeviceLoadDnsSettings(tundevice_tstate_t *state, const cJSON *settings);
bool tundeviceApplyDnsSettings(tundevice_tstate_t *state);
void tundeviceCleanupDnsSettings(tundevice_tstate_t *state);
void tundeviceFreeDnsSettings(tundevice_tstate_t *state);

void tundeviceOnIPPacketReceived(tun_device_t *tdev, void *userdata, sbuf_t *buf, wid_t wid);
void tundeviceTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf);

static inline void tundeviceClearEgressPinIfPublished(tundevice_tstate_t *state)
{
    if (state->egress_pin_published)
    {
        egressPinClear();
        state->egress_pin_published = false;
    }
}
