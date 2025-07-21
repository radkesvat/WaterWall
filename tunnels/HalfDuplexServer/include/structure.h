#pragma once

#include "wwapi.h"

#define i_type hmap_cons_t                        // NOLINT
#define i_key  hash_t                             // NOLINT
#define i_val  struct halfduplexserver_lstate_s * // NOLINT
#include "stc/hmap.h"

enum
{
    kHLFDCmdUpload   = 127,
    kHLFDCmdDownload = 128,
    kHmapCap         = 16 * 4,
    kMaxBuffering    = (65535 * 2)
};

enum connection_status
{
    kCsUnkown,
    kCsUploadInTable,
    kCsUploadDirect,
    kCsDownloadInTable,
    kCsDownloadDirect
};

typedef struct halfduplexserver_tstate_s
{
    wmutex_t    upload_line_map_mutex;
    hmap_cons_t upload_line_map;

    wmutex_t    download_line_map_mutex;
    hmap_cons_t download_line_map;
} halfduplexserver_tstate_t;

typedef struct halfduplexserver_lstate_s
{
    sbuf_t                *buffering;
    line_t                *upload_line;
    line_t                *download_line;
    line_t                *main_line;
    enum connection_status state;

    hash_t hash;
} halfduplexserver_lstate_t;

typedef struct notify_argument_s
{
    tunnel_t *self;
    hash_t    hash;
    uint8_t   tid;
} notify_argument_t;

enum
{
    kTunnelStateSize = sizeof(halfduplexserver_tstate_t),
    kLineStateSize   = sizeof(halfduplexserver_lstate_t)
};

WW_EXPORT void         halfduplexserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *halfduplexserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t halfduplexserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void halfduplexserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void halfduplexserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void halfduplexserverTunnelOnPrepair(tunnel_t *t);
void halfduplexserverTunnelOnStart(tunnel_t *t);

void halfduplexserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void halfduplexserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void halfduplexserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void halfduplexserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void halfduplexserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void halfduplexserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void halfduplexserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void halfduplexserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void halfduplexserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void halfduplexserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void halfduplexserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void halfduplexserverLinestateInitialize(halfduplexserver_lstate_t *ls);
void halfduplexserverLinestateDestroy(halfduplexserver_lstate_t *ls);
