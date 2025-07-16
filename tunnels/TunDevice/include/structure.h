#pragma once

#include "wwapi.h"

#include "devices/tun/tun.h"


#define LOG_PACKET_INFO 0
#define LOG_SSDP        0
#define LOG_MDNS        0
#define LOG_V6          0

typedef struct tundevice_tstate_s
{
    TunnelFlowRoutinePayload WriteReceivedPacket; // function to give received data to the next/prev tunnel

    // settings form json
    char *name;        // name of the device
    char *ip_subnet;   // ip/subnet
    char *ip_present;  //  only ip
    int   subnet_mask; // only subnet mask

    tun_device_t *tdev;

} tundevice_tstate_t;

typedef struct tundevice_lstate_s
{
    int unused;
} tundevice_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tundevice_tstate_t),
    kLineStateSize   = sizeof(tundevice_lstate_t)
};

WW_EXPORT void         tundeviceTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tundeviceTunnelCreate(node_t *node);
WW_EXPORT api_result_t tundeviceTunnelApi(tunnel_t *instance, sbuf_t *message);

void tundeviceTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void tundeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tundeviceTunnelOnPrepair(tunnel_t *t);
void tundeviceTunnelOnStart(tunnel_t *t);

void tundeviceTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tundeviceTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tundeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tundeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tundeviceTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tundeviceTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tundeviceTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tundeviceTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tundeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tundeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tundeviceTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tundeviceTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tundeviceLinestateInitialize(tundevice_lstate_t *ls);
void tundeviceLinestateDestroy(tundevice_lstate_t *ls);

void tundeviceOnIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t wid);
void tundeviceTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf);
