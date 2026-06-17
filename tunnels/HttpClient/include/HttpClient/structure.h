#pragma once

#include "wwapi.h"

#include "http2_def.h"
#include "http_def.h"
#include "nghttp2/nghttp2.h"

typedef enum httpclient_version_mode_e
{
    kHttpClientVersionModeHttp1 = 1,
    kHttpClientVersionModeHttp2 = 2,
    kHttpClientVersionModeBoth  = 3
} httpclient_version_mode_t;

typedef enum httpclient_runtime_proto_e
{
    kHttpClientRuntimeUnknown      = 0,
    kHttpClientRuntimeHttp1        = 1,
    kHttpClientRuntimeHttp2        = 2,
    kHttpClientRuntimeWaitUpgrade  = 3,
    kHttpClientRuntimeAfterUpgrade = 4,
    kHttpClientRuntimeUpgradedRaw  = 5
} httpclient_runtime_proto_t;

typedef enum httpclient_h1_body_mode_e
{
    kHttpClientH1BodyNone       = 0,
    kHttpClientH1BodyChunked    = 1,
    kHttpClientH1BodyContentLen = 2,
    kHttpClientH1BodyUntilClose = 3
} httpclient_h1_body_mode_t;

typedef enum httpclient_h1_transport_mode_e
{
    kHttpClientH1TransportSingle = 0,
    kHttpClientH1TransportSplit  = 1
} httpclient_h1_transport_mode_t;

typedef enum httpclient_split_role_e
{
    kHttpClientSplitRoleNone     = 0,
    kHttpClientSplitRoleMain     = 1,
    kHttpClientSplitRoleUpload   = 2,
    kHttpClientSplitRoleDownload = 3
} httpclient_split_role_t;

typedef struct httpclient_h2_data_item_s
{
    sbuf_t                           *payload;
    uint32_t                          offset;
    bool                              end_stream;
    bool                              complete;
    struct httpclient_h2_data_item_s *next;
} httpclient_h2_data_item_t;

typedef enum httpclient_split_placement_e
{
    kHttpClientSplitPlacementQuery  = 0,
    kHttpClientSplitPlacementHeader = 1,
    kHttpClientSplitPlacementCookie = 2,
    kHttpClientSplitPlacementPath   = 3
} httpclient_split_placement_t;

typedef struct httpclient_tstate_s
{
    nghttp2_session_callbacks *cbs;
    nghttp2_option            *ngoptions;

    char *scheme;
    char *path;
    char *host;
    char *method;
    char *user_agent;
    char *websocket_origin;
    char *websocket_subprotocol;
    char *websocket_extensions;
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

    enum http_method       method_enum;
    enum http_method       split_upload_method_enum;
    enum http_method       split_download_method_enum;
    enum http_content_type content_type;

    int host_port;

    uint8_t *upgrade_settings_payload;
    size_t   upgrade_settings_payload_len;
    char    *upgrade_settings_b64;

    httpclient_version_mode_t      version_mode;
    httpclient_h1_transport_mode_t h1_transport_mode;
    httpclient_split_placement_t   split_id_placement;
    httpclient_split_placement_t   split_direction_placement;
    httpclient_split_placement_t   split_token_placement;
    atomic_ullong                  split_identifier;
    bool                           enable_upgrade;
    bool                           websocket_enabled;
    bool                           full_duplex;
    bool                           split_cache_bypass;
    bool                           verbose;
} httpclient_tstate_t;

typedef struct httpclient_lstate_s
{
    tunnel_t *tunnel;
    line_t   *line;

    nghttp2_session *session;

    buffer_stream_t            in_stream;
    buffer_queue_t             pending_up;
    context_queue_t            events_down;
    httpclient_h2_data_item_t *h2_data_head;
    httpclient_h2_data_item_t *h2_data_tail;
    httpclient_h2_data_item_t *h2_data_active;

    httpclient_runtime_proto_t runtime_proto;

    int32_t h2_stream_id;

    int64_t h1_chunk_expected;
    int64_t h1_body_remaining;

    bool                      h1_headers_parsed;
    bool                      h1_response_chunked;
    bool                      h1_upgrade_accepted;
    httpclient_h1_body_mode_t h1_body_mode;

    bool h2_headers_received;
    bool response_complete;
    bool prev_finished;
    bool next_finished;

    bool fin_sent;

    bool websocket_active;
    bool websocket_waiting_handshake;
    bool websocket_close_sent;
    bool websocket_close_received;
    bool websocket_h2_waiting_connect;
    bool websocket_h2_request_submitted;
    bool websocket_h2_status_seen;
    bool websocket_h2_protocol_seen;
    bool websocket_h2_extensions_seen;
    int  websocket_h2_status_code;
    char websocket_key[32];
    char websocket_h2_protocol[128];
    char websocket_h2_extensions[256];

    httpclient_split_role_t split_role;
    line_t                 *split_main_line;
    line_t                 *split_upload_line;
    line_t                 *split_download_line;
    char                    split_id[48];
} httpclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(httpclient_tstate_t),
    kLineStateSize   = sizeof(httpclient_lstate_t),

    kHttpClientRequiredPaddingLeft = 16,

    kHttpClientBufferQueueCap   = 8,
    kHttpClientMaxHeaderBytes   = 64 * 1024,
    kHttpClientHttp2FrameBytes  = 32 * 1024,
    kHttpClientDefaultHttp1Port = 80,
    kHttpClientDefaultHttpsPort = 443
};

WW_EXPORT void         httpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *httpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void httpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void httpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void httpclientTunnelOnPrepair(tunnel_t *t);
void httpclientTunnelOnStart(tunnel_t *t);
void httpclientTunnelOnStop(tunnel_t *t);

void httpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void httpclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void httpclientLinestateInitialize(httpclient_lstate_t *ls, tunnel_t *t, line_t *l);
void httpclientLinestateDestroy(httpclient_lstate_t *ls);
void httpclientH2DataQueueDestroy(httpclient_lstate_t *ls);

bool    httpclientStringCaseEquals(const char *a, const char *b);
bool    httpclientStringCaseContains(const char *haystack, const char *needle);
bool    httpclientStringCaseContainsToken(const char *value, const char *token);
bool    bufferstreamFindCRLF(buffer_stream_t *stream, size_t *line_end);
bool    bufferstreamFindDoubleCRLF(buffer_stream_t *stream, size_t *header_end);
sbuf_t *allocBufferForLength(line_t *l, uint32_t len);

bool httpclientTransportSendHttp1RequestHeaders(tunnel_t *t, line_t *l, bool upgrade_to_h2);
bool httpclientTransportSendHttp1SplitRequestHeaders(tunnel_t *t, line_t *l);
bool httpclientTransportSendHttp1FinalChunk(tunnel_t *t, line_t *l);
bool httpclientTransportSendHttp1ChunkedPayload(tunnel_t *t, line_t *l, sbuf_t *payload);
bool httpclientTransportSendWebSocketData(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *payload,
                                          uint8_t opcode);
bool httpclientTransportSendWebSocketClose(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportDrainWebSocketDown(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);

bool httpclientTransportEnsureHttp2Session(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportHandleUpgradeAccepted(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportSendHttp2DataFrame(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *payload,
                                           bool end_stream);

bool httpclientTransportFlushPendingUp(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportFeedHttp2Input(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *buf);
bool httpclientTransportHandleHttp1ResponseHeaderPhase(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportDrainHttp1ChunkedBody(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
bool httpclientTransportDrainHttp1Body(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
void httpclientTransportCloseBothDirections(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);
void httpclientTransportCloseNextDirection(tunnel_t *t, line_t *l, httpclient_lstate_t *ls);

bool httpclientSplitIsEnabled(tunnel_t *t);
void httpclientSplitUpStreamInit(tunnel_t *t, line_t *l);
void httpclientSplitUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientSplitUpStreamFinish(tunnel_t *t, line_t *l);
void httpclientSplitDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientSplitDownStreamFinish(tunnel_t *t, line_t *l);
