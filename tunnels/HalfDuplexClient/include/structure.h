#pragma once

#include "wwapi.h"

enum
{
    kHLFDCmdUpload   = 127,
    kHLFDCmdDownload = 128
};


typedef struct halfduplexclient_tstate_s
{
    atomic_ullong identifier;
} halfduplexclient_tstate_t;

typedef struct halfduplexclient_lstate_s
{
    line_t *main_line;
    line_t *upload_line;
    line_t *download_line;
    bool    first_packet_sent;
} halfduplexclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(halfduplexclient_tstate_t),
    kLineStateSize   = sizeof(halfduplexclient_lstate_t)
};

WW_EXPORT void         halfduplexclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *halfduplexclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t halfduplexclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void halfduplexclientTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void halfduplexclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void halfduplexclientTunnelOnPrepair(tunnel_t *t);
void halfduplexclientTunnelOnStart(tunnel_t *t);

void halfduplexclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void halfduplexclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void halfduplexclientLinestateInitialize(halfduplexclient_lstate_t *ls, line_t *main_line);
void halfduplexclientLinestateDestroy(halfduplexclient_lstate_t *ls);
