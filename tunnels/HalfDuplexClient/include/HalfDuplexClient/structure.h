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

typedef struct halfduplexclient_tstate_s
{
    node_t        *upload_node;
    node_t        *download_node;
    tunnel_t      *upload_tunnel;
    tunnel_t      *download_tunnel;
    close_drain_t *drains[];
} halfduplexclient_tstate_t;

typedef enum halfduplexclient_intro_e
{
    kHalfDuplexIntroPending,
    kHalfDuplexDownloadIntroSent,
    kHalfDuplexUploadIntroSent
} halfduplexclient_intro_t;

typedef struct halfduplexclient_pair_s
{
    tunnel_t                *tunnel;
    line_t                  *main;
    line_t                  *upload;
    line_t                  *download;
    buffer_pool_t           *pool;
    buffer_queue_t           pending;
    sbuf_t                  *upload_intro;
    close_drain_t            deadline;
    unsigned                 refs;
    unsigned                 handoff_depth;
    halfduplexclient_intro_t intro;
    bool                     starting;
    bool                     pumping;
    bool                     ending;
    bool                     upload_paused;
    bool                     download_paused;
    bool                     download_read_paused;
    bool                     pending_read_pause;
    bool                     source_pause_sent;
    bool                     est_seen;
    bool                     est_forwarded;
} halfduplexclient_pair_t;

typedef struct halfduplexclient_lstate_s
{
    halfduplexclient_pair_t *pair;
} halfduplexclient_lstate_t;

enum
{
    kHalfDuplexClientMaxPendingBytes  = 2 * 1024 * 1024,
    kHalfDuplexClientMaxPendingCharge = 8U * 1024U * 1024U,
    kTunnelStateSize                  = sizeof(halfduplexclient_tstate_t),
    kLineStateSize                    = sizeof(halfduplexclient_lstate_t)
};

WW_EXPORT tunnel_t    *halfduplexclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t halfduplexclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void halfduplexclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

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

static inline halfduplexclient_pair_t *halfduplexclientGetPair(tunnel_t *t, line_t *line)
{
    return ((halfduplexclient_lstate_t *) lineGetState(line, t))->pair;
}

static inline void halfduplexclientSetPair(tunnel_t *t, line_t *line, halfduplexclient_pair_t *pair)
{
    ((halfduplexclient_lstate_t *) lineGetState(line, t))->pair = pair;
}

halfduplexclient_pair_t *halfduplexclientCreatePair(tunnel_t *t, line_t *main);
void                     halfduplexclientReleasePair(halfduplexclient_pair_t *pair);
void                     halfduplexclientDiscardUpload(halfduplexclient_pair_t *pair);
void                     halfduplexclientCloseChild(halfduplexclient_pair_t *pair, line_t **child, bool notify);
void                     halfduplexclientEndPair(halfduplexclient_pair_t *pair, const char *reason);
void                     halfduplexclientBeginDrain(halfduplexclient_pair_t *pair);
void                     halfduplexclientPump(halfduplexclient_pair_t *pair, sbuf_t *direct);
void                     halfduplexclientNotifyEstablished(halfduplexclient_pair_t *pair);
void                     halfduplexclientQuiesceDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void                     halfduplexclientStopDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void halfduplexclientSetNextPaused(tunnel_t *t, line_t *line, bool paused);
void halfduplexclientSetPrevPaused(tunnel_t *t, line_t *main, bool paused);
