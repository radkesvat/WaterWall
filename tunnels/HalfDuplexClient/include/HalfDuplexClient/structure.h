#pragma once

#include "wwapi.h"

enum
{
    kHLFDCmdUpload     = 127,
    kHLFDCmdDownload   = 128,
    kHLFDCommandOffset = 0,
    kHLFDPairIdOffset  = 1,
    kHLFDPairIdSize    = 16,
    kHLFDIntroSize     = kHLFDPairIdOffset + kHLFDPairIdSize
};

typedef struct halfduplexclient_lstate_s
{
    line_t *main_line;
    line_t *upload_line;
    line_t *download_line;
    bool    first_packet_sent;
    bool    next_started; // This exact owned child's adjacent Init was admitted.
    bool    next_paused;  // Child permission; main stores the aggregate producer hold.
    bool    read_pause_sent;
    bool    prev_paused;
    bool    source_pause_sent;
    bool    est_seen;
    bool    est_forwarded;
    bool    pair_initializing;
    bool    intro_dispatching;
    bool    draining;
    // Only main owns input held by pair Init, intro reentry or an older such backlog.
    buffer_queue_t pending_up;
} halfduplexclient_lstate_t;

enum
{
    kHalfDuplexClientMaxPendingBytes   = 2 * 1024 * 1024,
    kHalfDuplexClientMaxPendingBuffers = 1024,
    kTunnelStateSize                   = 0,
    kLineStateSize                     = sizeof(halfduplexclient_lstate_t)
};

WW_EXPORT tunnel_t    *halfduplexclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t halfduplexclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void halfduplexclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void halfduplexclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void halfduplexclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void halfduplexclientLinestateInitialize(halfduplexclient_lstate_t *ls, line_t *main_line);
void halfduplexclientLinestateDestroy(halfduplexclient_lstate_t *ls);

bool halfduplexclientPairAlive(tunnel_t *t, line_t *main, line_t *upload, line_t *download);
bool halfduplexclientNotifyEstablished(tunnel_t *t, line_t *main);
bool halfduplexclientDrainPending(tunnel_t *t, line_t *main, bool admitted);
bool halfduplexclientForwardPayload(tunnel_t *t, line_t *main, sbuf_t *buf);
void halfduplexclientClosePair(tunnel_t *t, line_t *line, bool from_prev, bool from_next);
void halfduplexclientSetNextPaused(tunnel_t *t, line_t *line, bool paused);
void halfduplexclientSetPrevPaused(tunnel_t *t, line_t *main, bool paused);
