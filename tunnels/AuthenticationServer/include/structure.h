#pragma once

#include "wwapi.h"


typedef struct authenticationserver_tstate_s
{
    char    *db_path;
    char    *backup_path;
    users_t  users;
    wtimer_t *save_timer;
    wrwlock_t sync_lock;
    wrecursive_mutex_t database_mutex;
    atomic_uint server_index;
    uint32_t file_save_rate_ms;
    bool     sync_lock_created;
    bool     database_mutex_created;
    bool     users_created;
    bool     database_loaded;
} authenticationserver_tstate_t;

typedef struct authenticationserver_lstate_s
{
    buffer_stream_t read_stream;
    buffer_queue_t  response_queue;
    bool            response_paused;
} authenticationserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(authenticationserver_tstate_t),
    kLineStateSize   = sizeof(authenticationserver_lstate_t),

    kAuthenticationServerMessageHeaderSize   = 4,
    kAuthenticationServerIndexHeaderSize     = 4,
    kAuthenticationServerEnvelopeHeaderSize  = kAuthenticationServerMessageHeaderSize + kAuthenticationServerIndexHeaderSize,
    kAuthenticationServerCorrelationIdSize   = 4,
    kAuthenticationServerRequestHeaderSize   = 1 + kAuthenticationServerCorrelationIdSize + 4,
    kAuthenticationServerResponseHeaderSize  = 1 + kAuthenticationServerCorrelationIdSize + 4,
    kAuthenticationServerMaxMessagePayload   = 16U * 1024U * 1024U,
    kAuthenticationServerMaxRequestData      = 16U * 1024U * 1024U,
    kAuthenticationServerMaxResponsePayload  = 16U * 1024U * 1024U,
    kAuthenticationServerMaxResponseQueue    = 16U * 1024U * 1024U,
    kAuthenticationServerResponseQueueCap    = 4,
    kAuthenticationServerMaxPasswordLength   = 1024U,

    kAuthenticationServerRequestTypePing                  = 1,
    kAuthenticationServerRequestTypeGetUserBySHA256Hex    = 2,
    kAuthenticationServerRequestTypeGetUserBySHA256Base64 = 3,
    kAuthenticationServerRequestTypeGetUserBySHA256       = 4,
    kAuthenticationServerRequestTypeGetUserByPassword     = 5,
    kAuthenticationServerRequestTypeAddNewUser            = 6,
    kAuthenticationServerRequestTypeUpdateUser            = 7,
    kAuthenticationServerRequestTypeUpdateUserTraficStatsDiff = 8,
    kAuthenticationServerRequestTypeGetAllUsers           = 9,
    kAuthenticationServerRequestTypePullChangesSync       = 10,

    kAuthenticationServerResponseTypeOk       = 0,
    kAuthenticationServerResponseTypeError    = 0xFF,
    kAuthenticationServerResponseTypePong     = 1,
    kAuthenticationServerResponseTypeUser     = 2,
    kAuthenticationServerResponseTypeUsers    = 3,
    kAuthenticationServerResponseTypeSyncUsers = 4
};

typedef sbuf_t *(*authenticationserver_module_handler_fn)(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len);

WW_EXPORT void         authenticationserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *authenticationserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t authenticationserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void authenticationserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void authenticationserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void authenticationserverTunnelOnPrepair(tunnel_t *t);
void authenticationserverTunnelOnStart(tunnel_t *t);

void authenticationserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void authenticationserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void authenticationserverLinestateInitialize(authenticationserver_lstate_t *ls, buffer_pool_t *pool);
void authenticationserverLinestateDestroy(authenticationserver_lstate_t *ls);

bool authenticationserverLoadDatabase(authenticationserver_tstate_t *ts);
bool authenticationserverSaveDatabase(authenticationserver_tstate_t *ts);
void authenticationserverSaveTimerCallback(wtimer_t *timer);
uint32_t authenticationserverGetServerIndex(tunnel_t *t);
bool authenticationserverMarkUserDirtyBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE]);
users_update_result_t authenticationserverUpdateUserBySHA256AndMarkDirty(tunnel_t *t,
                                                                         const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                                         const user_update_t *update);

bool authenticationserverProcessRequests(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls);
bool authenticationserverFlushResponses(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls);
void authenticationserverCloseLine(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls, const char *reason);

sbuf_t *authenticationserverCreateResponseFrame(
    line_t       *l,
    uint8_t       response_type,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    const uint8_t *response_data,
    uint32_t      response_data_len);

sbuf_t *authenticationserverCreateErrorResponseFrame(
    line_t       *l,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    const char   *error);

sbuf_t *authenticationserverCreateUserJsonResponseFrame(
    line_t       *l,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    cJSON        *user_json,
    const char   *module_name);

sbuf_t *authenticationserverDispatchRequest(
    uint8_t       request_type,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len);
bool authenticationserverRequestTypeReturnsUserState(uint8_t request_type);
bool authenticationserverRequestTypeBumpsSyncIndex(uint8_t request_type);
