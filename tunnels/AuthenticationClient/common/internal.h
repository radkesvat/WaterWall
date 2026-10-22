#pragma once

#include "structure.h"

/* Private client implementation. Worker-0 state stays owner-affine; Locked
 * helpers require the documented control/users lock ordering. */

uint64_t authenticationclientCounterDelta(uint64_t current, uint64_t baseline);

void authenticationclientRequiredWorkFailed(tunnel_t *t, const char *operation);

bool authenticationclientPendingAppend(authenticationclient_tstate_t *ts, uint32_t correlation_id, uint8_t request_type,
                                       uint64_t created_at_ms);

bool authenticationclientPendingRemove(authenticationclient_tstate_t *ts, uint32_t correlation_id,
                                       uint8_t *request_type_out);

void authenticationclientMarkRequestInFlightLocked(authenticationclient_tstate_t *ts, uint8_t request_type,
                                                   bool in_flight);

bool authenticationclientRequestMayBeSentLocked(authenticationclient_tstate_t *ts, uint8_t request_type);

void authenticationclientRemovePendingById(tunnel_t *t, uint32_t correlation_id);

bool authenticationclientSendRequest(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                     uint32_t request_data_len);

bool authenticationclientCloseTimedOutControlLine(tunnel_t *t);

bool authenticationclientSendAuthenticate(tunnel_t *t);

bool authenticationclientSendPing(tunnel_t *t);

bool authenticationclientHasCatchup(const authenticationclient_tstate_t *ts);

bool authenticationclientCaptureCatchup(tunnel_t *t);
bool authenticationclientPrepareTableDebt(authenticationclient_tstate_t *ts, users_t *dest,
                                          authenticationclient_accounting_entry_t **entries_out, size_t *count_out);
void authenticationclientInstallDebt(authenticationclient_tstate_t           *ts,
                                     authenticationclient_accounting_entry_t *entries, size_t count);
void authenticationclientDeferPull(tunnel_t *t, authenticationclient_failure_t failure);
bool authenticationclientRejectMissingBatch(tunnel_t *t, const uint8_t *data, uint32_t length);
bool authenticationclientIdDetachedLocked(authenticationclient_tstate_t *ts, uint64_t id);

bool authenticationclientSendPushUserStats(tunnel_t *t);

void authenticationclientResumeSync(tunnel_t *t);

bool authenticationclientAcknowledgeUsageBatch(tunnel_t *t, const uint8_t *data, uint32_t length);

void                           authenticationclientDestroyUsers(users_t *users);
void                           authenticationclientDiscardStaging(authenticationclient_tstate_t *ts);
authenticationclient_failure_t authenticationclientAcceptUsersPage(tunnel_t *t, const uint8_t *data, uint32_t length,
                                                                   uint64_t config_revision, uint64_t stats_revision,
                                                                   uint64_t generation, uint64_t received_at_ms);
bool                           authenticationclientSendUsersPage(tunnel_t *t);

void authenticationclientHandleResponseFrame(tunnel_t *t, line_t *l, uint8_t response_type, uint32_t correlation_id,
                                             const uint8_t *data, uint32_t data_len, uint64_t config_revision,
                                             uint64_t stats_revision, uint64_t received_at_ms);

void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish);

uint64_t authenticationclientRetryNotBeforeLocked(const authenticationclient_tstate_t *ts);
void     authenticationclientResetSyncRetryLocked(authenticationclient_tstate_t *ts);

/* Caller holds control_mutex -> users_lock. Availability is a snapshot; admission
 * and credential resolution recheck inside the same lock scope. */
authenticationclient_blocking_reason_t authenticationclientBlockingReasonLocked(
    const authenticationclient_tstate_t *ts);
authenticationclient_state_t authenticationclientStateLocked(const authenticationclient_tstate_t *ts);
bool                         authenticationclientCanAuthenticateLocked(const authenticationclient_tstate_t *ts);

void authenticationclientResetFirstUsagePushRuntime(tunnel_t *t);
