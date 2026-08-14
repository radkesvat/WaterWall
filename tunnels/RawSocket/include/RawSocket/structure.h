#pragma once

#include "wwapi.h"

#include "devices/capture/capture.h"
#include "devices/raw/raw.h"

enum capturedevice_direction_dynamic_value_status
{
    kDvsIncoming = kDvsFirstOption,
    kDvsOutgoing,
    kDvsBoth
};

enum capturedevice_filter_type_dynamic_value_status
{
    kDvsSourceIp = kDvsFirstOption,
    kDvsDestIp
};

typedef struct rawsocket_tstate_s
{
    packet_lifecycle_anchor_t lifecycle_anchor;

    capture_device_t *capture_device;
    ipmask_t         *capture_ranges;
    uint32_t          capture_range_count;
    char             *capture_device_name;
    uint32_t          except_fwmark;

    char         *raw_device_name;
    raw_device_t *raw_device;

    int firewall_mark;

} rawsocket_tstate_t;

_Static_assert(offsetof(rawsocket_tstate_t, lifecycle_anchor) == 0,
               "RawSocket lifecycle anchor must remain the tunnel-state prefix");

enum
{
    kTunnelStateSize = sizeof(rawsocket_tstate_t)
};

WW_EXPORT void         rawsocketDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *rawsocketCreate(node_t *node);
WW_EXPORT api_result_t rawsocketApi(tunnel_t *instance, sbuf_t *message);

void rawsocketOnStart(tunnel_t *t);
void rawsocketOnStop(tunnel_t *t);

void rawsocketExitHook(void *userdata, int sig);
void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid);
// bi-directional stream payload (upstream / downstream) to write to raw device
void rawsocketWriteStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
