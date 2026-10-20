#pragma once

#include "../../../Internals/AuthenticationCommon/wire.h"
#include "interface.h"

typedef struct authenticationclient_pending_request_s
{
    uint32_t correlation_id;
    uint64_t created_at_ms;
    uint8_t  request_type;
} authenticationclient_pending_request_t;

typedef struct authenticationclient_accounting_entry_s
{
    uint64_t  id;
    user_ud_t totals;
    user_ud_t delta;
    uint64_t  first_usage_at_ms;
} authenticationclient_accounting_entry_t;

/* Owned traversal metadata. No page is published before final validation. */
typedef struct authenticationclient_page_clock_s
{
    size_t   position, count;
    uint64_t server_time_ms, accounting_time_ms, received_at_ms;
} authenticationclient_page_clock_t;

typedef struct authenticationclient_staging_s
{
    users_t                           *users;
    authenticationclient_page_clock_t *clocks;
    size_t                             clock_count, clock_capacity;
    uint64_t                           total, position, encoded_bytes, config_revision, stats_revision;
    uint64_t                           revision_generation;
    char                               instance[33], cursor[65];
    bool                               active, complete;
} authenticationclient_staging_t;

typedef enum authenticationclient_failure_e
{
    kAuthenticationClientFailureNone = 0,
    kAuthenticationClientFailureTransportClosed,
    kAuthenticationClientFailureTimeout,
    kAuthenticationClientFailureCredentialRejected,
    kAuthenticationClientFailureContinuity,
    kAuthenticationClientFailureInvalidResponse,
    kAuthenticationClientFailureStatsPushDenied,
    kAuthenticationClientFailureStatsPushRejected,
    kAuthenticationClientFailureRemoteError,
    kAuthenticationClientFailureSyncLimit
} authenticationclient_failure_t;

typedef enum authenticationclient_blocking_reason_e
{
    kAuthenticationClientBlockNone = 0,
    kAuthenticationClientBlockStopping,
    kAuthenticationClientBlockNotStarted,
    kAuthenticationClientBlockContinuity,
    kAuthenticationClientBlockCredentialRejected,
    kAuthenticationClientBlockCacheClock
} authenticationclient_blocking_reason_t;

typedef enum authenticationclient_accounting_state_e
{
    kAuthenticationClientAccountingNotRequested = 0,
    kAuthenticationClientAccountingAvailable,
    kAuthenticationClientAccountingUnavailable
} authenticationclient_accounting_state_t;

/* Owned scalar values only; serialization never borrows live account state. */
typedef struct authenticationclient_status_s
{
    authenticationclient_state_t            state;
    authenticationclient_blocking_reason_t  blocking_reason;
    authenticationclient_accounting_state_t accounting_state;
    bool     started, stopping, connected, authenticated, auth_rejected, continuity_error;
    bool     users_loaded, clock_loaded, can_authenticate, write_paused;
    bool     auth_in_flight, pull_in_flight, push_in_flight, pull_requested, pull_required, push_requested;
    bool     catchup_capture_needed, reconnect_queued, unresolved_batch;
    bool     traversal_active;
    uint64_t sync_staged_users, sync_staged_bytes, sync_total_users;
    bool     first_usage_push_requested, first_usage_push_deferred;
    bool     retry_deadline_valid, request_deadline_valid;
    uint32_t sync_retry_streak;
    uint64_t sync_retry_remaining_ms;
    authenticationclient_failure_t sync_retry_failure;
    uint64_t users_count, pending_request_count, retained_catchup_slots;
    uint32_t traffic_multiplier; /* Fixed-point thousandths, as configured. */
    uint64_t batch_sequence, batch_entry_count, batch_size;
    uint64_t retry_remaining_ms, request_remaining_ms;
    uint64_t applied_config_revision, applied_stats_revision, applied_revision_generation;
    uint64_t remote_config_revision, remote_stats_revision, remote_revision_generation;
    bool     auth_success_valid, pull_success_valid, ack_success_valid;
    uint64_t auth_success_age_ms, pull_success_age_ms, ack_success_age_ms;
    authenticationclient_failure_t last_failure;
    uint8_t                        last_failure_operation;
    uint64_t                       last_failure_age_ms;
    uint64_t                       locally_unacknowledged_upload_bytes, locally_unacknowledged_download_bytes;
    uint64_t                       usage_user_count, first_use_observation_count;
    uint64_t                       sampling_started_ms, sampling_finished_ms;
    bool                           accounting_lower_bound;
} authenticationclient_status_t;

enum
{
    kAuthenticationClientBandwidthMaxTickets = 16384
};
typedef struct authenticationclient_bandwidth_ticket_s
{
    uint64_t                   id, user_id;
    user_bandwidth_direction_t direction;
    buffer_budget_cost_t       cost;
} authenticationclient_bandwidth_ticket_t;

typedef struct authenticationclient_tstate_s
{
    char *name;
    char *secret;

    users_t *users;
    users_t *sync_baseline_users;
    authenticationclient_staging_t staging; /* Worker 0, released after callbacks settle. */
    uint64_t                       sync_max_users, sync_max_bytes;
    /* Worker-0 owned value snapshots; no pointers into a replaceable table. */
    authenticationclient_accounting_entry_t *pending_entries;
    size_t                                   pending_entries_count;
    authenticationclient_accounting_entry_t *catchup_entries;
    size_t                                   catchup_entries_count;
    bool                                     catchup_capture_needed;
    wrwlock_t                                users_lock;
    uint64_t                                 users_generation;

    /* Shared costs and numeric ticket registry use control_mutex. Lock order:
     * control_mutex -> users_lock -> collection -> user -> stats. Registry costs
     * survive removal until their owner cancels/releases the unique ticket. */
    authenticationclient_bandwidth_ticket_t *bandwidth_tickets;
    buffer_budget_cost_t                     bandwidth_queued_cost;
    size_t                                   bandwidth_ticket_count;
    uint64_t                                 bandwidth_last_ticket;
    wmutex_t                                 control_mutex;
    bool                                     started;
    bool                                     stopping;
    bool                                     connected;
    bool                                     authenticated;
    bool                                     auth_rejected;
    bool                                     write_paused;
    bool                                     auth_in_flight;
    bool                                     pull_in_flight;
    bool                                     push_in_flight;
    bool                                     first_usage_push_requested;
    bool                                     first_usage_push_deferred;
    bool                                     users_loaded;
    bool                                     clock_loaded;
    bool                                     verbose;
    bool                                     reconnect_work_pending;
    bool                                     continuity_error;
    bool                                     stats_push_refused;
    bool                                     pull_requested;
    bool pull_required; /* Refresh after authentication or ACK, before a new usage batch. */
    bool push_requested;

    line_t   *control_line;
    wtimer_t *ping_timer;
    wtimer_t *sync_timer;
    wtimer_t *reconnect_timer;
    wtimer_t *request_timer;
    wtimer_t *progress_timer;
    uint64_t  reconnect_due_ms;
    uint64_t  stats_retry_not_before_ms;
    uint64_t                       sync_retry_not_before_ms;
    uint32_t                       sync_retry_streak;
    authenticationclient_failure_t sync_retry_failure;
    uint64_t  request_deadline_ms;

    uint8_t  token[64];
    char     accounting_epoch[65];
    uint64_t next_batch_sequence;
    uint64_t last_ack_sequence;
    uint8_t  last_ack_digest[SHA256_DIGEST_SIZE];
    char    *pending_batch;
    uint32_t pending_batch_length;
    uint32_t next_correlation_id;
    uint32_t ping_interval_ms;
    uint32_t pull_interval_ms;
    uint32_t push_interval_ms;
    uint32_t reconnect_interval_ms;
    uint32_t request_timeout_ms;
    uint32_t max_pending_requests;
    uint32_t traffic_multiplier; /* Immutable; new raw traffic only, in thousandths. */

    uint64_t remote_config_revision;
    uint64_t remote_stats_revision;
    uint64_t remote_revision_generation;
    uint64_t local_config_revision;
    uint64_t local_stats_revision;
    uint64_t local_revision_generation;

    uint32_t last_pull_sync_ms;
    uint32_t last_push_sync_ms;

    /* Historical monotonic facts, retained across reconnects. Zero is valid. */
    uint64_t                       last_auth_success_ms, last_pull_success_ms, last_ack_success_ms;
    bool                           last_auth_success_valid, last_pull_success_valid, last_ack_success_valid;
    authenticationclient_failure_t last_failure;
    uint8_t                        last_failure_operation;
    uint64_t                       last_failure_ms;

    authenticationclient_pending_request_t *pending_requests;
    uint32_t                                pending_count;
    uint32_t                                pending_capacity;
} authenticationclient_tstate_t;

typedef struct authenticationclient_lstate_s
{
    buffer_stream_t read_stream;
    bool            processing_responses;
} authenticationclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(authenticationclient_tstate_t),
    kLineStateSize   = sizeof(authenticationclient_lstate_t),

    kAuthenticationClientMessageHeaderSize          = kAuthenticationMessageHeaderSize,
    kAuthenticationClientSessionTokenSize           = kAuthenticationSessionTokenSize,
    kAuthenticationClientRevisionHeaderSize         = kAuthenticationRevisionHeaderSize,
    kAuthenticationClientRequestEnvelopeHeaderSize  = kAuthenticationRequestEnvelopeHeaderSize,
    kAuthenticationClientResponseEnvelopeHeaderSize = kAuthenticationResponseEnvelopeHeaderSize,
    kAuthenticationClientCorrelationIdSize          = kAuthenticationCorrelationIdSize,
    kAuthenticationClientRequestHeaderSize          = kAuthenticationRequestHeaderSize,
    kAuthenticationClientResponseHeaderSize         = kAuthenticationResponseHeaderSize,
    kAuthenticationClientMaxMessagePayload          = kAuthenticationMaxMessagePayload,
    kAuthenticationClientMaxRequestData             = kAuthenticationMaxRequestData,
    kAuthenticationClientMaxResponsePayload         = kAuthenticationMaxResponsePayload,
    kAuthenticationClientMaxBatchEntries            = kAuthenticationMaxBatchEntries,

    kAuthenticationClientRequestTypePing                  = kAuthenticationRequestTypePing,
    kAuthenticationClientRequestTypeGetUserBySHA256Hex    = kAuthenticationRequestTypeGetUserBySHA256Hex,
    kAuthenticationClientRequestTypeGetUserBySHA256Base64 = kAuthenticationRequestTypeGetUserBySHA256Base64,
    kAuthenticationClientRequestTypeGetUserBySHA256       = kAuthenticationRequestTypeGetUserBySHA256,
    kAuthenticationClientRequestTypeGetUserByPassword     = kAuthenticationRequestTypeGetUserByPassword,
    kAuthenticationClientRequestTypeAddNewUser            = kAuthenticationRequestTypeAddNewUser,
    kAuthenticationClientRequestTypeUpdateUser            = kAuthenticationRequestTypeUpdateUser,
    kAuthenticationClientRequestTypeGetUsersPage          = kAuthenticationRequestTypeGetUsersPage,
    kAuthenticationClientRequestTypeGetAllUsers           = kAuthenticationRequestTypeGetAllUsers,
    kAuthenticationClientRequestTypeAuthenticate          = kAuthenticationRequestTypeAuthenticate,
    kAuthenticationClientRequestTypePushUserStats         = kAuthenticationRequestTypePushUserStats,
    kAuthenticationClientRequestTypeGetUserBySHA224Hex    = kAuthenticationRequestTypeGetUserBySHA224Hex,
    kAuthenticationClientRequestTypeGetUserBySHA224Base64 = kAuthenticationRequestTypeGetUserBySHA224Base64,
    kAuthenticationClientRequestTypeGetUserBySHA224       = kAuthenticationRequestTypeGetUserBySHA224,

    kAuthenticationClientResponseTypeOk      = kAuthenticationResponseTypeOk,
    kAuthenticationClientResponseTypeError   = kAuthenticationResponseTypeError,
    kAuthenticationClientResponseTypePong    = kAuthenticationResponseTypePong,
    kAuthenticationClientResponseTypeUser    = kAuthenticationResponseTypeUser,
    kAuthenticationClientResponseTypeUsers   = kAuthenticationResponseTypeUsers,
    kAuthenticationClientResponseTypeSession = kAuthenticationResponseTypeSession,

    kAuthenticationClientDefaultPingIntervalMs      = 60U * 1000U,
    kAuthenticationClientDefaultPullIntervalMs      = 5U * 60U * 1000U,
    kAuthenticationClientDefaultPushIntervalMs      = 5U * 60U * 1000U,
    kAuthenticationClientDefaultReconnectIntervalMs = 5U * 1000U,
    kAuthenticationClientDefaultRequestTimeoutMs    = 120U * 1000U,
    kAuthenticationClientDefaultMaxPendingRequests  = 64U
};

enum
{
    kAuthenticationClientStatsRefusalMinRetryMs = 30U * 1000U
};

WW_EXPORT void         authenticationclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *authenticationclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t authenticationclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void authenticationclientTunnelOnStart(tunnel_t *t);
void authenticationclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void authenticationclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void authenticationclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void authenticationclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void authenticationclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void authenticationclientLinestateInitialize(authenticationclient_lstate_t *ls, buffer_pool_t *pool);
void authenticationclientLinestateDestroy(authenticationclient_lstate_t *ls);

void authenticationclientOpenControlLine(tunnel_t *t);
void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish);
void authenticationclientRecoverControlLine(tunnel_t *t, line_t *l, bool propagate_finish);
void authenticationclientUpdateRequestTimer(tunnel_t *t);
void authenticationclientScheduleSyncProgress(tunnel_t *t);
bool authenticationclientCloseTimedOutControlLine(tunnel_t *t);
void authenticationclientScheduleReconnect(tunnel_t *t);
void authenticationclientReconnectTimerCallback(wtimer_t *timer);
void authenticationclientPingTimerCallback(wtimer_t *timer);
bool authenticationclientStartSyncTimer(tunnel_t *t);
void authenticationclientSyncTimerCallback(wtimer_t *timer);

void authenticationclientStatusSnapshot(tunnel_t *t, bool include_accounting, size_t working_allowance,
                                        uint64_t deadline_ms, authenticationclient_status_t *out);
void authenticationclientRecordFailure(tunnel_t *t, authenticationclient_failure_t failure, uint8_t operation);
bool authenticationclientRegisterApi(tunnel_t *t);

bool authenticationclientSendAuthenticate(tunnel_t *t);
bool authenticationclientSendPing(tunnel_t *t);
bool authenticationclientSendGetAllUsers(tunnel_t *t);
bool authenticationclientSendPushUserStats(tunnel_t *t);
void authenticationclientResumeSync(tunnel_t *t);
bool authenticationclientProcessResponses(tunnel_t *t, line_t *l, authenticationclient_lstate_t *ls);

static inline uint64_t authenticationclientLocalTimeMS(void)
{
    return getHRTimeUs() / 1000ULL;
}
