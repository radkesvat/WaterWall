#pragma once

#include "wwapi.h"

enum
{
    kHLFDCmdUpload     = 127,
    kHLFDCmdDownload   = 128,
    kHLFDCommandOffset = 0,
    kHLFDPairIdOffset  = 1,
    kHLFDPairIdSize    = 16,
    kHLFDIntroSize     = kHLFDPairIdOffset + kHLFDPairIdSize,
    kHmapCap           = 16 * 4,
    kMaxBuffering      = (65535 * 2)
};

typedef struct halfduplex_pair_id_s
{
    uint8_t bytes[kHLFDPairIdSize];
} halfduplex_pair_id_t;

static inline size_t halfduplexPairIdHash(const halfduplex_pair_id_t *pair_id)
{
    return (size_t) calcHashBytes(pair_id->bytes, sizeof(pair_id->bytes));
}

static inline bool halfduplexPairIdEqual(const halfduplex_pair_id_t *left, const halfduplex_pair_id_t *right)
{
    return memoryCompare(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

#define i_type hmap_cons_t                        // NOLINT
#define i_key  halfduplex_pair_id_t               // NOLINT
#define i_val  struct halfduplexserver_lstate_s * // NOLINT
#define i_hash halfduplexPairIdHash               // NOLINT
#define i_eq   halfduplexPairIdEqual              // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

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
    wmutex_t    pending_line_maps_mutex;
    hmap_cons_t upload_line_map;
    hmap_cons_t download_line_map;
    bool        pending_line_maps_mutex_initialized;
} halfduplexserver_tstate_t;

typedef struct halfduplexserver_lstate_s
{
    sbuf_t                *buffering;
    line_t                *upload_line;
    line_t                *download_line;
    line_t                *main_line;
    enum connection_status state;

    halfduplex_pair_id_t pair_id;
} halfduplexserver_lstate_t;

typedef enum halfduplexserver_pending_result_e
{
    kHalfDuplexServerPendingInserted,
    kHalfDuplexServerPendingDuplicate,
    kHalfDuplexServerPendingMatchedLocal,
    kHalfDuplexServerPendingMatchedRemote
} halfduplexserver_pending_result_e;

typedef struct halfduplexserver_pending_decision_s
{
    halfduplexserver_pending_result_e result;
    halfduplexserver_lstate_t        *peer;
    wid_t                             target_wid;
} halfduplexserver_pending_decision_t;

enum
{
    kTunnelStateSize = sizeof(halfduplexserver_tstate_t),
    kLineStateSize   = sizeof(halfduplexserver_lstate_t)
};

WW_EXPORT void         halfduplexserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *halfduplexserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t halfduplexserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void halfduplexserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void halfduplexserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void halfduplexserverTunnelOnPrepair(tunnel_t *t);
void halfduplexserverTunnelOnStart(tunnel_t *t);
void halfduplexserverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

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

#ifdef WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM
halfduplexserver_pending_decision_t halfduplexserverTestPendingClaim(halfduplexserver_tstate_t *ts,
                                                                     halfduplexserver_lstate_t *ls,
                                                                     halfduplex_pair_id_t pair_id, bool is_upload,
                                                                     sbuf_t *buf);
void                                halfduplexserverPendingBeforeLockTestSeam(bool is_upload);
void                                halfduplexserverPendingMissTestSeam(bool is_upload);
#endif
