#pragma once

#include "audit.h"
#include "wwapi.h"

typedef enum authenticationserver_save_result_e
{
    kAuthenticationServerSaveNotAttempted = 0,
    kAuthenticationServerSaveSuccess,
    kAuthenticationServerSaveFailure
} authenticationserver_save_result_t;

typedef struct authenticationserver_status_s
{
    bool                                  database_loaded;
    bool                                  database_dirty, primary_checkpoint_valid;
    size_t                                user_count;
    uint32_t                              configured_producer_count;
    uint32_t                              session_record_count;
    uint64_t                              config_revision;
    uint64_t                              stats_revision;
    uint8_t                               instance_id[16];
    authenticationserver_save_result_t    primary_save_last_result;
    bool                                  primary_save_last_attempt_valid;
    bool                                  primary_save_last_success_valid;
    uint64_t                              primary_save_last_attempt_age_ms;
    uint64_t                              primary_save_last_success_age_ms;
    authenticationserver_audit_snapshot_t audit;
} authenticationserver_status_t;

typedef enum authenticationserver_status_result_e
{
    kAuthenticationServerStatusOk = 0,
    kAuthenticationServerStatusBusy,
    kAuthenticationServerStatusTimeout
} authenticationserver_status_result_t;

/* Constant-size, side-effect-free snapshot. deadline_ms uses monotonic time;
 * zero means no deadline. Failure leaves a zeroed output, never partial data. */
authenticationserver_status_result_t authenticationserverStatusSnapshot(tunnel_t *t, uint64_t deadline_ms,
                                                                        authenticationserver_status_t *out);
