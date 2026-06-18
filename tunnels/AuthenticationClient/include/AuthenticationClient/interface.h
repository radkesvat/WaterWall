#pragma once

#include "objects/user.h"
#include "objects/user_handle.h"
#include "wwapi.h"

typedef enum authenticationclient_state_e
{
    kAuthenticationClientStateStopped = 0,
    kAuthenticationClientStateConnecting,
    kAuthenticationClientStateAuthenticating,
    kAuthenticationClientStateReady
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
    kAuthenticationClientUserLookupUserLimitReached
} authenticationclient_user_lookup_result_t;

WW_EXPORT node_t nodeAuthenticationClientGet(void);

/*
 * Internal Waterwall API.
 *
 * Other tunnels should include this header and use handles plus copy-out helpers.
 * The AuthenticationClient never exposes user_t pointers from its private users_t
 * table; returned handles are value identifiers. Generation-gated read helpers
 * may reject handles after a full GetAllUsers replacement, while enforcement
 * helpers resolve by durable user id with SHA-256 fallback.
 */
WW_EXPORT authenticationclient_state_t authenticationclientGetState(tunnel_t *t);
WW_EXPORT bool                         authenticationclientIsReady(tunnel_t *t);
WW_EXPORT uint64_t                     authenticationclientUsersGeneration(tunnel_t *t);

WW_EXPORT bool authenticationclientGetUserByPassword(tunnel_t *t, const char *password, user_handle_t *handle_out);
WW_EXPORT authenticationclient_user_lookup_result_t
authenticationclientGetUserByPasswordWithResult(tunnel_t *t, const char *password, user_handle_t *handle_out);
WW_EXPORT const char *authenticationclientUserLookupResultString(authenticationclient_user_lookup_result_t result);
WW_EXPORT bool        authenticationclientGetUserBySHA224(tunnel_t *t, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                                          user_handle_t *handle_out);
WW_EXPORT bool        authenticationclientGetUserBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE],
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

WW_EXPORT authenticationclient_user_lookup_result_t authenticationclientGetUserByPasswordWithProfile(
    tunnel_t *t, const char *password, user_handle_t *handle_out, authenticationclient_user_profile_t *profile_out);
WW_EXPORT bool authenticationclientUserHandleIsLive(tunnel_t *t, const user_handle_t *handle);

WW_EXPORT cJSON *authenticationclientUserToJson(tunnel_t *t, const user_handle_t *handle);
WW_EXPORT cJSON *authenticationclientUsersToJson(tunnel_t *t);
WW_EXPORT bool   authenticationclientUserGetStats(tunnel_t *t, const user_handle_t *handle, user_stat_t *stats_out);
WW_EXPORT bool   authenticationclientUserAddTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                                    uint64_t download_bytes);

WW_EXPORT void authenticationclientRequestPull(tunnel_t *t);
WW_EXPORT void authenticationclientRequestPush(tunnel_t *t);

/*
 * Live connection-admission and enforcement helpers for traffic-serving nodes
 * such as UserController. They resolve the handle against the current local
 * users table by durable user id when present, or by SHA-256 key for legacy users,
 * and run the matching runtime helper.
 * They touch only process-local runtime state and cumulative traffic counters, never synced
 * configuration. now_ms is in the AuthenticationClient/UserController local-clock domain; pulled
 * server expiry fields are projected into that domain when GetAllUsers is installed.
 */
WW_EXPORT user_admission_result_t authenticationclientUserTryAdmitConnection(tunnel_t *t, const user_handle_t *handle,
                                                                             const user_ip_key_t *ip_key,
                                                                             uint64_t             now_ms);
WW_EXPORT void                    authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle,
                                                                            const user_ip_key_t *ip_key);
/* Adds traffic to the user and returns whether the connection must now be closed. */
WW_EXPORT bool authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                                      uint64_t download_bytes, uint64_t now_ms);
/* True when an already-open connection for this user must be closed (disabled, expired, over quota). */
WW_EXPORT bool authenticationclientUserShouldClose(tunnel_t *t, const user_handle_t *handle, uint64_t now_ms);
