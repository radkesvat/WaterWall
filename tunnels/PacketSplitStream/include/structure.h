#pragma once

#include "wwapi.h"

typedef struct packetsplitstream_tstate_s
{
    node_t   *up_node;
    node_t   *down_node;
    tunnel_t *up_tunnel;
    tunnel_t *down_tunnel;
} packetsplitstream_tstate_t;

typedef struct packetsplitstream_lstate_s
{
    int unused;
} packetsplitstream_lstate_t;

enum
{
    kTunnelStateSize = sizeof(packetsplitstream_tstate_t),
    kLineStateSize   = sizeof(packetsplitstream_lstate_t)
};

WW_EXPORT void         packetsplitstreamTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *packetsplitstreamTunnelCreate(node_t *node);
WW_EXPORT api_result_t packetsplitstreamTunnelApi(tunnel_t *instance, sbuf_t *message);

void packetsplitstreamTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void packetsplitstreamTunnelOnStart(tunnel_t *t);
void packetsplitstreamTunnelOnStop(tunnel_t *t);
void packetsplitstreamTunnelOnPrepair(tunnel_t *t);

void packetsplitstreamTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetsplitstreamTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetsplitstreamTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetsplitstreamTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetsplitstreamTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetsplitstreamLinestateInitializePacket(packetsplitstream_lstate_t *ls);

void packetsplitstreamLinestateDestroy(packetsplitstream_lstate_t *ls);

line_t *packetsplitstreamEnsureUploadLine(tunnel_t *t, line_t *packet_line, packetsplitstream_lstate_t *packet_ls);
line_t *packetsplitstreamEnsureDownloadLine(tunnel_t *t, line_t *packet_line, packetsplitstream_lstate_t *packet_ls);
void    packetsplitstreamEnsureSplitLines(tunnel_t *t, line_t *packet_line, packetsplitstream_lstate_t *packet_ls);
void    packetsplitstreamDestroyOwnedLine(tunnel_t *t, line_t **slot);
