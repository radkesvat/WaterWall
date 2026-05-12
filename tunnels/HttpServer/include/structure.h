#pragma once

#include "wwapi.h"

#include "bufio/buffer_stream.h"
#include "http2_def.h"
#include "http_def.h"
#include "nghttp2/nghttp2.h"

#define i_type hmap_httpserver_split_t      // NOLINT
#define i_key  hash_t                       // NOLINT
#define i_val  struct httpserver_lstate_s  *// NOLINT
#include "stc/hmap.h"

typedef enum httpserver_version_mode_e
{
    kHttpServerVersionModeHttp1 = 1,
    kHttpServerVersionModeHttp2 = 2,
    kHttpServerVersionModeBoth  = 3
} httpserver_version_mode_t;

typedef enum httpserver_runtime_proto_e
{
    kHttpServerRuntimeUnknown     = 0,
    kHttpServerRuntimeHttp1       = 1,
    kHttpServerRuntimeHttp2       = 2,
    kHttpServerRuntimeUpgradedRaw = 3
} httpserver_runtime_proto_t;

typedef enum httpserver_h1_body_mode_e
{
    kHttpServerH1BodyNone       = 0,
    kHttpServerH1BodyChunked    = 1,
    kHttpServerH1BodyContentLen = 2
} httpserver_h1_body_mode_t;

typedef enum httpserver_h1_transport_mode_e
{
    kHttpServerH1TransportSingle = 0,
    kHttpServerH1TransportSplit  = 1
} httpserver_h1_transport_mode_t;

typedef enum httpserver_split_role_e
{
    kHttpServerSplitRoleNone     = 0,
    kHttpServerSplitRoleUnknown  = 1,
    kHttpServerSplitRoleUpload   = 2,
    kHttpServerSplitRoleDownload = 3,
    kHttpServerSplitRoleMain     = 4
} httpserver_split_role_t;

typedef enum httpserver_split_placement_e
{
    kHttpServerSplitPlacementQuery  = 0,
    kHttpServerSplitPlacementHeader = 1,
    kHttpServerSplitPlacementCookie = 2,
    kHttpServerSplitPlacementPath   = 3
} httpserver_split_placement_t;

typedef struct httpserver_lstate_s
{
    tunnel_t *tunnel;
    line_t   *line;

    nghttp2_session *session;

    buffer_stream_t in_stream;
    buffer_queue_t  pending_down;
    context_queue_t events_up;

    httpserver_runtime_proto_t runtime_proto;

    int32_t h2_stream_id;

    int64_t h1_chunk_expected;
    int64_t h1_body_remaining;

    bool                      h1_headers_parsed;
    bool                      h1_request_chunked;
    bool                      h1_request_finished;
    bool                      h1_response_headers_sent;
    httpserver_h1_body_mode_t h1_body_mode;

    bool h2_response_headers_sent;
    bool h2_request_finished;

    bool fin_sent;
    bool prev_finished;
    bool next_finished;

    bool h2_reject_extra_streams;

    bool websocket_active;
    bool websocket_close_sent;
    bool websocket_close_received;
    bool websocket_h2_method_seen;
    bool websocket_h2_protocol_seen;
    bool websocket_h2_path_seen;
    bool websocket_h2_authority_seen;
    bool websocket_h2_version_seen;
    bool websocket_h2_subprotocol_seen;
    bool websocket_h2_origin_seen;
    char websocket_h2_method[16];
    char websocket_h2_protocol[32];
    char websocket_h2_path[2048];
    char websocket_h2_authority[512];
    char websocket_h2_version[16];
    char websocket_h2_subprotocol[256];
    char websocket_h2_origin[512];

    httpserver_split_role_t split_role;
    line_t                 *split_main_line;
    line_t                 *split_upload_line;
    line_t                 *split_download_line;
    buffer_queue_t          split_pending_up;
    hash_t                  split_hash;
} httpserver_lstate_t;

typedef struct httpserver_tstate_s
{
    nghttp2_session_callbacks *cbs;
    nghttp2_option            *ngoptions;

    char *expected_host;
    char *expected_path;
    char *expected_method;
    char *websocket_origin;
    char *websocket_subprotocol;
    char *upgrade_protocol;
    char *split_upload_method;
    char *split_download_method;
    char *split_upload_path;
    char *split_download_path;
    char *split_id_name;
    char *split_direction_name;
    char *split_upload_value;
    char *split_download_value;
    char *split_cache_bypass_name;
    char *split_token;
    char *split_token_name;

    const cJSON *headers;
    const cJSON *upgrade_request_headers;
    const cJSON *upgrade_response_headers;
    const cJSON *split_upload_headers;
    const cJSON *split_download_headers;

    enum http_method       expected_method_enum;
    enum http_method       split_upload_method_enum;
    enum http_method       split_download_method_enum;
    enum http_content_type content_type;
    int                    status_code;

    wmutex_t                split_upload_map_mutex;
    wmutex_t                split_download_map_mutex;
    hmap_httpserver_split_t split_upload_map;
    hmap_httpserver_split_t split_download_map;

    httpserver_version_mode_t      version_mode;
    httpserver_h1_transport_mode_t h1_transport_mode;
    httpserver_split_placement_t   split_id_placement;
    httpserver_split_placement_t   split_direction_placement;
    httpserver_split_placement_t   split_token_placement;
    bool                           enable_upgrade;
    bool                           websocket_enabled;
    bool                           full_duplex;
    bool                           split_cache_bypass;
    bool                           split_maps_initialized;
    bool                           no_split_upload_buffering_limit;
    bool                           verbose;
} httpserver_tstate_t;

enum
{
    kTunnelStateSize = sizeof(httpserver_tstate_t),
    kLineStateSize   = sizeof(httpserver_lstate_t),

    kHttpServerRequiredPaddingLeft = 16,

    kHttpServerBufferQueueCap    = 8,
    kHttpServerMaxHeaderBytes    = 64 * 1024,
    kHttpServerHttp2FrameBytes   = 32 * 1024,
    kHttpServerSplitMaxBuffering = 65535 * 2,
    kHttpServerDefaultHttp1Port  = 80,
    kHttpServerDefaultHttpsPort  = 443
};

WW_EXPORT void         httpserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *httpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void httpserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void httpserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void httpserverTunnelOnPrepair(tunnel_t *t);
void httpserverTunnelOnStart(tunnel_t *t);

void httpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void httpserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void httpserverLinestateInitialize(httpserver_lstate_t *ls, tunnel_t *t, line_t *l);
void httpserverLinestateDestroy(httpserver_lstate_t *ls);

bool    httpserverStringCaseEquals(const char *a, const char *b);
bool    httpserverStringCaseContains(const char *haystack, const char *needle);
bool    httpserverStringCaseContainsToken(const char *value, const char *token);
bool    httpserverBufferstreamFindCRLF(buffer_stream_t *stream, size_t *line_end);
bool    httpserverBufferstreamFindDoubleCRLF(buffer_stream_t *stream, size_t *header_end);
sbuf_t *httpserverAllocBufferForLength(line_t *l, uint32_t len);

bool httpserverTransportSendHttp1ResponseHeaders(tunnel_t *t, line_t *l);
bool httpserverTransportSendHttp1FinalChunk(tunnel_t *t, line_t *l);
bool httpserverTransportSendHttp1ChunkedPayload(tunnel_t *t, line_t *l, sbuf_t *payload);
bool httpserverTransportSendWebSocketData(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *payload,
                                          uint8_t opcode);
bool httpserverTransportSendWebSocketClose(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportDrainWebSocketUp(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);

bool httpserverTransportPrepareHttp2Session(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportEnsureHttp2Session(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportSubmitHttp2ResponseHeaders(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, bool end_stream);
bool httpserverTransportSendHttp2DataFrame(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *payload,
                                           bool end_stream);

bool httpserverTransportFlushPendingDown(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportDrainRawUp(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportFeedHttp2Input(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *buf);
bool httpserverTransportDetectRuntimeProtocol(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportHandleHttp1RequestHeaderPhase(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportDrainHttp1ChunkedRequestBody(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
bool httpserverTransportDrainHttp1RequestBody(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);
void httpserverTransportCloseBothDirections(tunnel_t *t, line_t *l, httpserver_lstate_t *ls);

bool httpserverSplitIsEnabled(tunnel_t *t);
void httpserverSplitUpStreamInit(tunnel_t *t, line_t *l);
void httpserverSplitUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverSplitUpStreamFinish(tunnel_t *t, line_t *l);
void httpserverSplitDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverSplitDownStreamFinish(tunnel_t *t, line_t *l);
