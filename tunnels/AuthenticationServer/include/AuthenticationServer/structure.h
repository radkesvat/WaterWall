#pragma once

#include "../../../Internals/AuthenticationCommon/wire.h"
#include "audit.h"
#include "status.h"
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
    authenticationserver_audit_t              *audit;
    char                                      *db_path;
    char                                      *backup_path;
    char                                      *normal_backups_path;
    authenticationserver_users_store_t         store;
    authenticationserver_auth_client_t        *auth_clients;
    authenticationserver_session_t           **sessions;
    wtimer_t                                  *save_timer;
    wtimer_t                                  *session_expiry_timer;
    wrwlock_t                                  state_lock;
    uint8_t                                    api_instance_id[16];
    uint32_t                                   auth_clients_count;
    uint32_t                                   sessions_count;
    uint32_t                                   sessions_capacity;
    uint32_t                                   file_save_rate_ms;
    uint32_t                                   session_idle_timeout_ms;
    uint32_t                                   normal_backups_count_limit;
    uint64_t                                   normal_backups_last_slot;
    uint64_t                                   accounting_anchor_ms;
    uint64_t                                   accounting_monotonic_ms;
    uint64_t                                   primary_save_last_attempt_ms;
    uint64_t                                   primary_save_last_success_ms;
    size_t                                     max_user_export_bytes;
    authenticationserver_normal_backups_mode_t normal_backups_mode;
    authenticationserver_save_result_t         primary_save_last_result;
    bool                                       primary_save_last_attempt_valid;
    bool                                       primary_save_last_success_valid;
    bool                                       database_loaded;
    bool                                       database_dirty;
    bool                                       primary_checkpoint_valid;
    bool                                       periodic_save_seen;
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
    bool                        reject_further_input;
} authenticationserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(authenticationserver_tstate_t),
    kLineStateSize   = sizeof(authenticationserver_lstate_t),

    kAuthenticationServerMessageHeaderSize          = kAuthenticationMessageHeaderSize,
    kAuthenticationServerSessionTokenSize           = kAuthenticationSessionTokenSize,
    kAuthenticationServerRevisionHeaderSize         = kAuthenticationRevisionHeaderSize,
    kAuthenticationServerRequestEnvelopeHeaderSize  = kAuthenticationRequestEnvelopeHeaderSize,
    kAuthenticationServerResponseEnvelopeHeaderSize = kAuthenticationResponseEnvelopeHeaderSize,
    kAuthenticationServerCorrelationIdSize          = kAuthenticationCorrelationIdSize,
    kAuthenticationServerRequestHeaderSize          = kAuthenticationRequestHeaderSize,
    kAuthenticationServerResponseHeaderSize         = kAuthenticationResponseHeaderSize,
    kAuthenticationServerMaxMessagePayload          = kAuthenticationMaxMessagePayload,
    kAuthenticationServerMaxRequestData             = kAuthenticationMaxRequestData,
    kAuthenticationServerMaxResponsePayload         = kAuthenticationMaxResponsePayload,
    kAuthenticationServerMaxResponseQueue   = 16U * 1024U * 1024U + kAuthenticationServerResponseEnvelopeHeaderSize,
    kAuthenticationServerMaxResponseCharge  = 32U * 1024U * 1024U,
    kAuthenticationServerMaxResponseEntries = 1024,
    kAuthenticationServerOutputChunkSize    = 16U * 1024U,
    kAuthenticationServerMaxBatchEntries            = kAuthenticationMaxBatchEntries,
    kAuthenticationServerMaxFramesPerEnvelope = 64,
    kAuthenticationServerResponseQueueCap               = 4,
    kAuthenticationServerDefaultNormalBackupsCountLimit = 10U,
    kAuthenticationServerDefaultSessionIdleTimeoutMs    = 10U * 60U * 1000U,
    kAuthenticationServerSessionExpirySweepMs           = 60U * 1000U,

    kAuthenticationServerRequestTypePing                  = kAuthenticationRequestTypePing,
    kAuthenticationServerRequestTypeGetUserBySHA256Hex    = kAuthenticationRequestTypeGetUserBySHA256Hex,
    kAuthenticationServerRequestTypeGetUserBySHA256Base64 = kAuthenticationRequestTypeGetUserBySHA256Base64,
    kAuthenticationServerRequestTypeGetUserBySHA256       = kAuthenticationRequestTypeGetUserBySHA256,
    kAuthenticationServerRequestTypeGetUserByPassword     = kAuthenticationRequestTypeGetUserByPassword,
    kAuthenticationServerRequestTypeAddNewUser            = kAuthenticationRequestTypeAddNewUser,
    kAuthenticationServerRequestTypeUpdateUser            = kAuthenticationRequestTypeUpdateUser,
    kAuthenticationServerRequestTypeGetUsersPage          = kAuthenticationRequestTypeGetUsersPage,
    kAuthenticationServerRequestTypeGetAllUsers           = kAuthenticationRequestTypeGetAllUsers,
    kAuthenticationServerRequestTypeAuthenticate          = kAuthenticationRequestTypeAuthenticate,
    kAuthenticationServerRequestTypePushUserStats         = kAuthenticationRequestTypePushUserStats,
    kAuthenticationServerRequestTypeGetUserBySHA224Hex    = kAuthenticationRequestTypeGetUserBySHA224Hex,
    kAuthenticationServerRequestTypeGetUserBySHA224Base64 = kAuthenticationRequestTypeGetUserBySHA224Base64,
    kAuthenticationServerRequestTypeGetUserBySHA224       = kAuthenticationRequestTypeGetUserBySHA224,

    kAuthenticationServerResponseTypeOk      = kAuthenticationResponseTypeOk,
    kAuthenticationServerResponseTypeError   = kAuthenticationResponseTypeError,
    kAuthenticationServerResponseTypePong    = kAuthenticationResponseTypePong,
    kAuthenticationServerResponseTypeUser    = kAuthenticationResponseTypeUser,
    kAuthenticationServerResponseTypeUsers   = kAuthenticationResponseTypeUsers,
    kAuthenticationServerResponseTypeSession = kAuthenticationResponseTypeSession
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
typedef enum authenticationserver_save_reason_e
{
    kAuthenticationServerSaveForced,
    kAuthenticationServerSavePeriodic,
    kAuthenticationServerSaveShutdown,
    kAuthenticationServerSaveProducerCreate
} authenticationserver_save_reason_t;
bool     authenticationserverSaveDatabaseForReason(authenticationserver_tstate_t     *ts,
                                                   authenticationserver_save_reason_t reason);
bool     authenticationserverSaveDatabaseLockedForReason(authenticationserver_tstate_t     *ts,
                                                         authenticationserver_save_reason_t reason);
void     authenticationserverSaveTimerCallback(wtimer_t *timer);
void     authenticationserverSessionExpiryTimerCallback(wtimer_t *timer);
void     authenticationserverGetRevisions(tunnel_t *t, uint64_t *config_revision, uint64_t *stats_revision);
void     authenticationserverBumpConfigRevision(tunnel_t *t);
void     authenticationserverBumpStatsRevision(tunnel_t *t);
void     authenticationserverInitializeAccountingClock(authenticationserver_tstate_t *ts);
void     authenticationserverInitializeExportLimit(authenticationserver_tstate_t *ts);
uint64_t authenticationserverAccountingTimeMS(const authenticationserver_tstate_t *ts);
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
/* Validate the token in the unread prefix without retaining a session pointer. */
bool authenticationserverInputTokenValid(tunnel_t *t, buffer_stream_t *stream, const sbuf_t *input);
bool authenticationserverInputAllowance(tunnel_t *t, buffer_stream_t *stream, const sbuf_t *input, bool *ordinary_out);
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
