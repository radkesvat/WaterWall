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
    capture_device_t *capture_device;
    char             *capture_ip;
    char             *capture_device_name;
    uint32_t          except_fwmark;

    char         *raw_device_name;
    raw_device_t *raw_device;

    char *onexit_command;

    int  firewall_mark;
    bool write_direction_upstream; // this means we write to upstream when receiving packets

} rawsocket_tstate_t;

typedef struct rawsocket_lstate_s
{
    int unused;
} rawsocket_lstate_t;

enum
{
    kTunnelStateSize = sizeof(rawsocket_tstate_t),
    kLineStateSize   = sizeof(rawsocket_lstate_t)
};

WW_EXPORT void         rawsocketDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *rawsocketCreate(node_t *node);
WW_EXPORT api_result_t rawsocketApi(tunnel_t *instance, sbuf_t *message);

void rawsocketOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void rawsocketOnChain(tunnel_t *t, tunnel_chain_t *chain);
void rawsocketOnPrepair(tunnel_t *t);
void rawsocketOnStart(tunnel_t *t);

void rawsocketUpStreamInit(tunnel_t *t, line_t *l);
void rawsocketUpStreamEst(tunnel_t *t, line_t *l);
void rawsocketUpStreamFinish(tunnel_t *t, line_t *l);
void rawsocketUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rawsocketUpStreamPause(tunnel_t *t, line_t *l);
void rawsocketUpStreamResume(tunnel_t *t, line_t *l);

void rawsocketDownStreamInit(tunnel_t *t, line_t *l);
void rawsocketDownStreamEst(tunnel_t *t, line_t *l);
void rawsocketDownStreamFinish(tunnel_t *t, line_t *l);
void rawsocketDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rawsocketDownStreamPause(tunnel_t *t, line_t *l);
void rawsocketDownStreamResume(tunnel_t *t, line_t *l);

void rawsocketLinestateInitialize(rawsocket_lstate_t *ls);
void rawsocketLinestateDestroy(rawsocket_lstate_t *ls);

void rawsocketExitHook(void *userdata, int sig);
void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid);
// bi-directional stream payload (upstream / downstream) to write to raw device
void rawsocketWriteStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
