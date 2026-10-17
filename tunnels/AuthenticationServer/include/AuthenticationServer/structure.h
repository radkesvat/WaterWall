#pragma once

#include "wwapi.h"

typedef struct authenticationserver_users_store_s
{
    users_t  users;
    uint64_t config_revision;
    uint64_t stats_revision;
} authenticationserver_users_store_t;

typedef struct authenticationserver_auth_client_s
{
    char    *name;
    char    *secret;
    bool     allow_stats_push;
    bool     allow_user_pull;
    bool     allow_user_write;
    uint32_t session_idle_timeout_ms;
    uint8_t  accounting_epoch[64];
    uint64_t last_sequence;
    uint8_t  last_digest[SHA256_DIGEST_SIZE];
} authenticationserver_auth_client_t;

typedef enum authenticationserver_normal_backups_mode_e
{
    kAuthenticationServerNormalBackupsDisabled = 0,
    kAuthenticationServerNormalBackupsHourly,
    kAuthenticationServerNormalBackupsDaily,
    kAuthenticationServerNormalBackupsWeekly
} authenticationserver_normal_backups_mode_t;

typedef struct authenticationserver_session_s
{
    uint8_t     token[64];
    char       *client_name;
    authenticationserver_auth_client_t *accounting_client;
    uint8_t                             accounting_epoch[64];
    bool        allow_stats_push;
    bool        allow_user_pull;
    bool                                allow_user_write;
    atomic_uint last_activity_ms;
    uint32_t    session_idle_timeout_ms;
} authenticationserver_session_t;

typedef struct authenticationserver_tstate_s
{
    char                                      *db_path;
    char                                      *backup_path;
    char                                      *normal_backups_path;
    authenticationserver_users_store_t         store;
    authenticationserver_auth_client_t        *auth_clients;
    authenticationserver_session_t           **sessions;
    wtimer_t                                  *save_timer;
    wtimer_t                                  *session_expiry_timer;
    wrwlock_t                                  state_lock;
    uint32_t                                   auth_clients_count;
    uint32_t                                   sessions_count;
    uint32_t                                   sessions_capacity;
    uint32_t                                   file_save_rate_ms;
    uint32_t                                   session_idle_timeout_ms;
    uint32_t                                   normal_backups_count_limit;
    uint64_t                                   normal_backups_last_slot;
    authenticationserver_normal_backups_mode_t normal_backups_mode;
    bool                                       database_loaded;
    bool                                       verbose;
} authenticationserver_tstate_t;

typedef struct authenticationserver_lstate_s
{
    buffer_stream_t read_stream;
    buffer_queue_t  response_queue;
    buffer_budget_t             response_budget;
    buffer_budget_reservation_t active_response_cost;
    sbuf_t                     *active_response;
    buffer_pool_t              *pool;
    bool            response_paused;
    bool                        response_draining;
    bool                        processing_requests;
} authenticationserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(authenticationserver_tstate_t),
    kLineStateSize   = sizeof(authenticationserver_lstate_t),

    kAuthenticationServerMessageHeaderSize  = 4,
    kAuthenticationServerSessionTokenSize   = 64,
    kAuthenticationServerRevisionHeaderSize = 16,
    kAuthenticationServerRequestEnvelopeHeaderSize =
        kAuthenticationServerMessageHeaderSize + kAuthenticationServerSessionTokenSize,
    kAuthenticationServerResponseEnvelopeHeaderSize =
        kAuthenticationServerMessageHeaderSize + kAuthenticationServerRevisionHeaderSize,
    kAuthenticationServerCorrelationIdSize              = 4,
    kAuthenticationServerRequestHeaderSize              = 1 + kAuthenticationServerCorrelationIdSize + 4,
    kAuthenticationServerResponseHeaderSize             = 1 + kAuthenticationServerCorrelationIdSize + 4,
    kAuthenticationServerMaxMessagePayload              = 16U * 1024U * 1024U,
    kAuthenticationServerMaxRequestData                 = 16U * 1024U * 1024U,
    kAuthenticationServerMaxResponsePayload             = 16U * 1024U * 1024U,
    kAuthenticationServerMaxResponseQueue   = 16U * 1024U * 1024U + kAuthenticationServerResponseEnvelopeHeaderSize,
    kAuthenticationServerMaxResponseCharge  = 32U * 1024U * 1024U,
    kAuthenticationServerMaxResponseEntries = 1024,
    kAuthenticationServerOutputChunkSize    = 16U * 1024U,
    kAuthenticationServerMaxBatchEntries    = 4096,
    kAuthenticationServerResponseQueueCap               = 4,
    kAuthenticationServerMaxPasswordLength              = 1024U,
    kAuthenticationServerDefaultNormalBackupsCountLimit = 10U,
    kAuthenticationServerDefaultSessionIdleTimeoutMs    = 10U * 60U * 1000U,
    kAuthenticationServerSessionExpirySweepMs           = 60U * 1000U,

    kAuthenticationServerRequestTypePing                      = 1,
    kAuthenticationServerRequestTypeGetUserBySHA256Hex        = 2,
    kAuthenticationServerRequestTypeGetUserBySHA256Base64     = 3,
    kAuthenticationServerRequestTypeGetUserBySHA256           = 4,
    kAuthenticationServerRequestTypeGetUserByPassword         = 5,
    kAuthenticationServerRequestTypeAddNewUser                = 6,
    kAuthenticationServerRequestTypeUpdateUser                = 7,
    kAuthenticationServerRequestTypeGetAllUsers               = 9,
    kAuthenticationServerRequestTypeAuthenticate              = 10,
    kAuthenticationServerRequestTypePushUserStats             = 11,
    kAuthenticationServerRequestTypeGetUserBySHA224Hex        = 12,
    kAuthenticationServerRequestTypeGetUserBySHA224Base64     = 13,
    kAuthenticationServerRequestTypeGetUserBySHA224           = 14,

    kAuthenticationServerResponseTypeOk      = 0,
    kAuthenticationServerResponseTypeError   = 0xFF,
    kAuthenticationServerResponseTypePong    = 1,
    kAuthenticationServerResponseTypeUser    = 2,
    kAuthenticationServerResponseTypeUsers   = 3,
    kAuthenticationServerResponseTypeSession = 4
};

typedef sbuf_t *(*authenticationserver_module_handler_fn)(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len);

WW_EXPORT void         authenticationserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *authenticationserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t authenticationserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void authenticationserverTunnelOnStart(tunnel_t *t);
void authenticationserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void authenticationserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void authenticationserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void authenticationserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void authenticationserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void authenticationserverLinestateInitialize(authenticationserver_lstate_t *ls, buffer_pool_t *pool);
void authenticationserverLinestateDestroy(authenticationserver_lstate_t *ls);

bool authenticationserverLoadDatabase(authenticationserver_tstate_t *ts);
bool authenticationserverSaveDatabaseLocked(authenticationserver_tstate_t *ts);
bool authenticationserverSaveDatabase(authenticationserver_tstate_t *ts);
void authenticationserverSaveTimerCallback(wtimer_t *timer);
void authenticationserverSessionExpiryTimerCallback(wtimer_t *timer);
void authenticationserverGetRevisions(tunnel_t *t, uint64_t *config_revision, uint64_t *stats_revision);
void authenticationserverBumpConfigRevision(tunnel_t *t);
void authenticationserverBumpStatsRevision(tunnel_t *t);
/* Called inside the request's state_lock write serialization. */
users_update_result_t           authenticationserverPatchConfigAndBumpRevision(tunnel_t *t, uint64_t id,
                                                                               const user_config_patch_t *patch);
bool                            authenticationserverUserHasRequiredId(const user_t *user);
authenticationserver_session_t *authenticationserverSessionCreate(tunnel_t *t, const char *name, const char *secret,
                                                                  const uint8_t *resume_epoch, const char **error);
authenticationserver_session_t *authenticationserverSessionFindByTokenLocked(
    tunnel_t *t, const uint8_t token[kAuthenticationServerSessionTokenSize]);
void authenticationserverSessionTouch(authenticationserver_session_t *session, uint32_t now_ms);
void authenticationserverSessionsExpireIdle(tunnel_t *t);
void authenticationserverSessionsDestroy(authenticationserver_tstate_t *ts);
void authenticationserverAuthClientsDestroy(authenticationserver_tstate_t *ts);

bool authenticationserverProcessRequests(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls);
bool authenticationserverFlushResponses(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls);
void authenticationserverCloseLine(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls, const char *reason);

sbuf_t *authenticationserverCreateResponseFrame(line_t *l, uint8_t response_type,
                                                const uint8_t  correlation_id[kAuthenticationServerCorrelationIdSize],
                                                const uint8_t *response_data, uint32_t response_data_len);

sbuf_t *authenticationserverCreateErrorResponseFrame(
    line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], const char *error);

sbuf_t *authenticationserverCreateUserJsonResponseFrame(
    line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], cJSON *user_json,
    const char *module_name);

bool authenticationserverUserJsonWireGuardAllowedIpsValid(const cJSON *user_json);
/* Bounded wire serialization; caller frees with cJSON_free(). */
char *authenticationserverSerializeResponseJson(const cJSON *json);

sbuf_t *authenticationserverDispatchRequest(uint8_t       request_type,
                                            const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                            tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                            const uint8_t *request_data, uint32_t request_data_len);
