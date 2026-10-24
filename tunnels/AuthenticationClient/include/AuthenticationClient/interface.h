#pragma once

#include "wwapi.h"

typedef enum authenticationclient_state_e
{
    kAuthenticationClientStateStopped = 0,
    kAuthenticationClientStateConnecting,
    kAuthenticationClientStateAuthenticating,
    kAuthenticationClientStateReady,
    kAuthenticationClientStateContinuityError
} authenticationclient_state_t;

typedef enum authenticationclient_user_lookup_result_e
{
    kAuthenticationClientUserLookupOk = 0,
    kAuthenticationClientUserLookupInvalidArgument,
    kAuthenticationClientUserLookupHashFailed,
    kAuthenticationClientUserLookupUsersUnavailable,
    kAuthenticationClientUserLookupUserNotFound,
    kAuthenticationClientUserLookupPasswordMismatch,
    kAuthenticationClientUserLookupUserDisabled,
    kAuthenticationClientUserLookupUserExpired,
    kAuthenticationClientUserLookupUserLimitReached,
    kAuthenticationClientUserLookupUserIdRequired
} authenticationclient_user_lookup_result_t;

WW_EXPORT node_t nodeAuthenticationClientGet(void);

/*
 * Internal Waterwall API.
 *
 * Legacy lookup and ordinary handle helpers return an invalid/unavailable result
 * for a NULL tunnel. The payload
 * observation and bandwidth helpers require a non-NULL tunnel and valid handle;
 * callers also own their documented direction/ticket preconditions.
 *
 * Other tunnels should include this header and use handles plus copy-out helpers.
 * The AuthenticationClient never exposes user_t pointers from its private users_t
 * table; returned handles are value identifiers keyed by durable user id.
 * Generation-gated read helpers may require the exact current table generation.
 * Enforcement helpers resolve by durable user id and the membership-generation
 * floor: refresh preserves continuous membership; removal/recreation revokes old
 * handles even if the durable id is reused.
 */
WW_EXPORT authenticationclient_state_t authenticationclientGetState(tunnel_t *t);
WW_EXPORT bool                         authenticationclientIsReady(tunnel_t *t);
/* Admission from the last valid RAM cache, independently of transport state. */
WW_EXPORT bool     authenticationclientCanAuthenticate(tunnel_t *t);
WW_EXPORT uint64_t authenticationclientUsersGeneration(tunnel_t *t);

typedef user_uuid_candidate_t authenticationclient_uuid_candidate_t;

typedef struct authenticationclient_uuid_source_s
{
    uint64_t users_generation;
    size_t   total_users;
    size_t   max_users;
    size_t   max_bytes;
} authenticationclient_uuid_source_t;

typedef enum authenticationclient_uuid_snapshot_result_e
{
    kAuthenticationClientUuidSnapshotOk,
    kAuthenticationClientUuidSnapshotUnavailable,
    kAuthenticationClientUuidSnapshotChanged,
    kAuthenticationClientUuidSnapshotLimit
} authenticationclient_uuid_snapshot_result_t;

/* Constant-work metadata for the installed, admission-capable RAM table. Limits
 * are this client's sync-max-users/sync-max-bytes, not a process-wide RAM cap.
 * Failure clears source_out. NULL tunnels report Unavailable. */
WW_EXPORT authenticationclient_uuid_snapshot_result_t
authenticationclientGetUUIDSource(tunnel_t *t, authenticationclient_uuid_source_t *source_out);

/* Copy at most max_rows SOURCE rows, not matched UUIDs; max_rows is 1..256
 * (kUsersUuidCandidatePageMax) and entries_out has that many slots. Each call
 * checks expected_generation under table ownership. Changed/Unavailable/Limit
 * clears count/next and leaves entries unchanged. Success may return no UUIDs
 * before the terminal source position. Values are owned copies; securely wipe
 * them after use. No crypto, allocation, or caller callback runs under the locks. */
WW_EXPORT authenticationclient_uuid_snapshot_result_t authenticationclientCopyUUIDCandidatePage(
    tunnel_t *t, uint64_t expected_generation, size_t position, size_t max_rows,
    authenticationclient_uuid_candidate_t *entries_out, size_t *count_out, size_t *next_position_out);

WW_EXPORT bool authenticationclientGetUserByPassword(tunnel_t *t, const char *password, user_handle_t *handle_out);
WW_EXPORT authenticationclient_user_lookup_result_t
authenticationclientGetUserByPasswordWithResult(tunnel_t *t, const char *password, user_handle_t *handle_out);
WW_EXPORT const char *authenticationclientUserLookupResultString(authenticationclient_user_lookup_result_t result);
WW_EXPORT bool        authenticationclientGetUserBySHA224(tunnel_t *t, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                                          user_handle_t *handle_out);
WW_EXPORT bool        authenticationclientGetUserBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          user_handle_t *handle_out);
WW_EXPORT bool        authenticationclientGetUserByUUID(tunnel_t *t, const uint8_t uuid[kWwUuidBytesLen],
                                                        user_handle_t *handle_out);
WW_EXPORT bool        authenticationclientGetUserByWireGuardPublicKey(tunnel_t      *t,
                                                                      const uint8_t  publickey[USER_WIREGUARD_PUBLICKEY_SIZE],
                                                                      user_handle_t *handle_out);

/*
 * Resolved copies of a user's identity fields, taken in the same locked lookup
 * that produced the handle (a consistent snapshot, no second lookup / stale
 * handle). Both fields are stringDuplicate-d and owned by the caller, which must
 * release them with authenticationclientUserProfileClear(). Either may be NULL
 * when the user record has no value for it.
 */
typedef struct authenticationclient_user_profile_s
{
    char *name;     // account name
    char *password; // raw password
} authenticationclient_user_profile_t;

WW_EXPORT void authenticationclientUserProfileClear(authenticationclient_user_profile_t *profile);

WW_EXPORT bool authenticationclientGetUserBySHA224WithProfile(tunnel_t *t, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                                              user_handle_t                       *handle_out,
                                                              authenticationclient_user_profile_t *profile_out);

WW_EXPORT authenticationclient_user_lookup_result_t authenticationclientGetUserByUUIDWithProfile(
    tunnel_t *t, const uint8_t uuid[kWwUuidBytesLen], user_handle_t *handle_out,
    authenticationclient_user_profile_t *profile_out);
/* Resolve a copied candidate only if its UUID still belongs to the same durable
 * id and continuously present membership. A full refresh preserves matching
 * identities; removal/recreation, reassignment, or future generations fail with
 * UserNotFound. Current eligibility/profile and the returned current-generation
 * handle are resolved together. No snapshot pointer is retained. */
WW_EXPORT authenticationclient_user_lookup_result_t authenticationclientResolveUUIDCandidateWithProfile(
    tunnel_t *t, uint64_t source_generation, const authenticationclient_uuid_candidate_t *candidate,
    user_handle_t *handle_out, authenticationclient_user_profile_t *profile_out);
WW_EXPORT authenticationclient_user_lookup_result_t authenticationclientGetUserByWireGuardPublicKeyWithProfile(
    tunnel_t *t, const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE], user_handle_t *handle_out,
    authenticationclient_user_profile_t *profile_out);
WW_EXPORT authenticationclient_user_lookup_result_t authenticationclientGetUserByPasswordWithProfile(
    tunnel_t *t, const char *password, user_handle_t *handle_out, authenticationclient_user_profile_t *profile_out);
WW_EXPORT bool authenticationclientUserHandleIsLive(tunnel_t *t, const user_handle_t *handle);

/* Trusted, credential-bearing full exports; returned trees belong to the caller
 * and must be deleted with cJSON_Delete(). The whole-table export allocates and
 * serializes every account while holding table/collection read locks. Use the
 * existing redacted status/projection APIs for public diagnostics. The single
 * user export requires the handle's exact current table generation. */
WW_EXPORT cJSON *authenticationclientUserToJson(tunnel_t *t, const user_handle_t *handle);
WW_EXPORT cJSON *authenticationclientUsersToJson(tunnel_t *t);
WW_EXPORT bool   authenticationclientUserGetStats(tunnel_t *t, const user_handle_t *handle, user_stat_t *stats_out);
/* Traffic inputs are actual measured bytes. Both accounting APIs apply this
 * client's configured multiplier once; returned traffic stats are charged bytes. */
WW_EXPORT bool authenticationclientUserAddTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                                  uint64_t download_bytes);

WW_EXPORT void authenticationclientRequestPull(tunnel_t *t);
WW_EXPORT void authenticationclientRequestPush(tunnel_t *t);

/*
 * Live connection-admission and enforcement helpers for traffic-serving nodes
 * such as UserController. They resolve the handle against the current local
 * users table by durable user id plus its membership-generation floor and run
 * the matching runtime helper. Recreated ids do not revive old handles.
 * They touch only process-local runtime state and cumulative traffic counters, never synced
 * configuration. now_ms is in the local monotonic domain used for admission/sweeps.
 * Traffic accounting samples fresh time inside the user write lock, records first
 * local use, and enforces expiry there; the supplied sample may already be stale.
 */
WW_EXPORT user_admission_result_t authenticationclientUserTryAdmitConnection(tunnel_t *t, const user_handle_t *handle,
                                                                             const user_ip_key_t *ip_key,
                                                                             uint64_t             now_ms);
WW_EXPORT void                    authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle,
                                                                            const user_ip_key_t *ip_key);
/* Adds measured traffic at the configured rate and returns whether the connection
 * must now be closed. First use follows raw activity even if its charge is <1 byte. */
WW_EXPORT bool authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                                      uint64_t download_bytes, uint64_t now_ms);
/* True when an already-open connection for this user must be closed (disabled, expired, over quota). */
WW_EXPORT bool authenticationclientUserShouldClose(tunnel_t *t, const user_handle_t *handle, uint64_t now_ms);

/* UserController arrival observation does not charge quota or multiplier carry. */
WW_EXPORT bool authenticationclientUserObservePayload(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                                      uint64_t download_bytes, uint64_t now_ms);
/* Tickets are client-unique and never reused. Registration starts ineligible;
 * activate after queue admission. Cancellation releases all remaining costs. */
WW_EXPORT uint64_t authenticationclientUserBandwidthRegister(tunnel_t *t, const user_handle_t *handle,
                                                             user_bandwidth_direction_t direction);
WW_EXPORT void     authenticationclientUserBandwidthSetEligible(tunnel_t *t, const user_handle_t *handle,
                                                                user_bandwidth_direction_t direction, uint64_t ticket,
                                                                bool eligible);
WW_EXPORT void     authenticationclientUserBandwidthCancel(tunnel_t *t, const user_handle_t *handle,
                                                           user_bandwidth_direction_t direction, uint64_t ticket);
WW_EXPORT bool     authenticationclientUserBandwidthReserve(tunnel_t *t, const user_handle_t *handle, uint64_t ticket,
                                                            buffer_budget_cost_t cost);
WW_EXPORT void     authenticationclientUserBandwidthRelease(tunnel_t *t, const user_handle_t *handle, uint64_t ticket,
                                                            buffer_budget_cost_t cost);
WW_EXPORT user_bandwidth_result_t  authenticationclientUserBandwidthPreview(tunnel_t *t, const user_handle_t *handle,
                                                                            user_bandwidth_direction_t direction,
                                                                            uint64_t ticket, uint64_t bytes,
                                                                            bool datagram);
WW_EXPORT user_delivery_decision_t authenticationclientUserCommitDelivery(tunnel_t *t, const user_handle_t *handle,
                                                                          user_bandwidth_direction_t direction,
                                                                          uint64_t ticket, uint64_t bytes,
                                                                          bool datagram, bool more);
