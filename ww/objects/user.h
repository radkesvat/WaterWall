#pragma once

/*
 * User model, lifecycle, JSON persistence, and usage helpers.
 *
 * Ownership:
 * - user_t itself is caller-owned. userCreate(), userCreateFromJson(), and
 *   userCopy() initialize caller-provided storage; they do not allocate the
 *   user_t object.
 * - userDestroy() releases all memory owned by an initialized user_t. It is
 *   also safe to call on zeroed user_t storage.
 *
 * Thread safety:
 * - Public helpers acquire the per-user locks they need.
 * - The struct is visible for compatibility, but callers should not mutate
 *   fields directly. Direct writes bypass locks and may desynchronize users_t
 *   lookup tables when the user is database-owned.
 *
 * Password changes:
 * - userChangePassword() updates only this one user_t and is safe for
 *   standalone users.
 * - If the user_t is stored inside a users_t database, use
 *   usersChangePassword() instead so database lookup indexes are updated.
 */

#include "wlibc.h"

#include "cJSON.h"
#include "wmutex.h"
#include "wcrypto.h"

#define USER_NO_LIMIT                        0ULL
#define USER_NO_EXPIRY                       0ULL
#define USER_DEFAULT_RECORD_STAT_INTERVAL_MS 120000

typedef struct user_ud_s
{
    uint64_t u;
    uint64_t d;
} user_ud_t;

typedef user_ud_t ud_t;

typedef struct user_traffic_limit_s
{
    uint64_t u;
    uint64_t d;
    uint64_t total;
} user_traffic_limit_t;

typedef struct user_limit_s
{
    user_traffic_limit_t traffic;
    user_ud_t            bandwidth;
    uint64_t             ips;
    uint64_t             devices;
    uint64_t             cons_in;
    uint64_t             cons_out;
} user_limit_t;

typedef struct user_time_info_s
{
    uint64_t created_at_ms;
    uint64_t first_usage_at_ms;
    uint64_t expire_at_ms;
    uint64_t expire_after_first_usage_ms;
} user_time_info_t;

typedef struct user_stat_s
{
    uint64_t  ips;
    uint64_t  devices;
    uint64_t  cons_in;
    uint64_t  cons_out;
    user_ud_t speed;
    user_ud_t traffic;
} user_stat_t;

/*
 * Compact, lwIP-independent representation of a peer IP address.
 *
 * Enforcement nodes (for example UserController) convert the connecting peer's
 * ip_addr_t into this value before handing it to the runtime helpers, so the
 * core user object does not need to depend on the socket/lwIP headers.
 * type == 0 means "no IP" and disables per-user IP-count tracking for that
 * connection.
 */
typedef struct user_ip_key_s
{
    uint8_t type;     // address family discriminator (0 == none)
    uint8_t bytes[16]; // raw address bytes in network order (IPv4 uses the first 4)
} user_ip_key_t;

/*
 * Result of an admission decision. Only kUserAdmissionOk reserves a connection
 * slot; every other value is a rejection reason for logging.
 */
typedef enum user_admission_result_e
{
    kUserAdmissionOk = 0,
    kUserAdmissionDisabled,
    kUserAdmissionExpired,
    kUserAdmissionTrafficLimited,
    kUserAdmissionConnectionLimited,
    kUserAdmissionIpLimited,
    kUserAdmissionInvalid
} user_admission_result_t;

/*
 * Per-IP usage entry for the live runtime tracker. refs counts how many active
 * connections currently originate from that exact IP.
 */
typedef struct user_ip_usage_s
{
    user_ip_key_t key;
    uint64_t      refs;
} user_ip_usage_t;

/*
 * Live, process-local enforcement state. Unlike user_stat_t this is never
 * serialized, copied, or synced to AuthenticationServer; it is recreated empty
 * whenever the user object is (re)created and tracks only currently-open
 * connections for limit enforcement. Guarded by user_s.stats_lock.
 */
typedef struct user_runtime_stat_s
{
    uint64_t         active_cons_out;
    user_ip_usage_t *ip_usages;
    size_t           ip_usage_count;
    size_t           ip_usage_capacity;
    bool             first_usage_push_requested;
} user_runtime_stat_t;

typedef struct user_s User;
typedef User          user_t;

struct user_s
{
    wrwlock_t lock;
    wrwlock_t stats_lock;
    bool      initialized;

    char *name;
    char *password;
    char *email;
    char *notes;

    uint64_t id;
    hash_t gid;
    bool   enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    /*
     * Runtime-only client projection of server-owned expiry time. When valid,
     * expiry checks compare against this local-clock deadline instead of the
     * persisted server-clock timeinfo fields. Never serialized or copied.
     */
    uint64_t client_view_expires_at_ms;
    bool     client_view_expiry_valid;
    int              record_stat_interval_ms;

    user_stat_t stats;

    user_runtime_stat_t runtime;

    /*
     * These hashes are laid out for 32-byte operations, but the field attributes
     * only help if the containing user_t object itself is 32-byte aligned.
     * users_t-owned users satisfy that through aligned block allocation; callers
     * with standalone/stack users must not use strict aligned helpers unless
     * they also provide aligned storage.
     */
    hash_t        hash_pass;
    uint8_t       sha_alignment_padding[8];
    MSVC_ATTR_ALIGNED_32 sha224_hash_t sha224_pass GNU_ATTR_ALIGNED_32;
    uint8_t       sha224_pass_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
    MSVC_ATTR_ALIGNED_32 sha256_hash_t sha256_pass GNU_ATTR_ALIGNED_32;

    bool sha224_pass_valid;
    bool sha256_pass_valid;
};

bool userCreate(User *user, const char *password);
bool userCreateFromJson(User *user, const cJSON *user_json);
/* Standalone/deep-copy helpers. For users_t-owned users, prefer usersAddUser()/usersUpdateUser(). */
bool userCopy(User *dest, const User *src);
void userDestroy(User *user);

cJSON *userToJson(User *user);

bool userChangePassword(User *user, const char *password);
/* Compatibility alias for userChangePassword(); prefer usersChangePassword() for database-owned users. */
bool userSetPassword(User *user, const char *password);
bool userPasswordMatches(User *user, const char *password);
bool userPasswordDataValid(User *user);

void userSetEnabled(User *user, bool enabled);
bool userIsEnabled(User *user);
uint64_t userGetId(User *user);
void     userSetId(User *user, uint64_t id);
bool userIsDisabled(User *user);
bool userIsExpired(User *user, uint64_t now_ms);
bool userIsActive(User *user, uint64_t now_ms);
bool userIsTrafficLimited(User *user);
bool userHasReachedTrafficLimit(User *user);
bool userHasReachedBandwidthLimit(User *user);
bool userHasReachedLimit(User *user);

/*
 * Live connection-admission and accounting helpers used by enforcement nodes.
 *
 * These operate on the process-local user_s.runtime state and are independent
 * from the serialized user_s.stats counters.
 */
user_admission_result_t userTryAdmitConnection(User *user, const user_ip_key_t *ip_key, uint64_t now_ms);
void                    userReleaseConnection(User *user, const user_ip_key_t *ip_key);
/*
 * Adds traffic to the cumulative stats and reports whether the connection must now be closed.
 * first_usage_push_needed is set once, at the first non-zero traffic accounting while first_usage_at_ms
 * is still missing, so AuthenticationClient can ask the server to stamp first usage promptly.
 */
bool userAccountTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                        bool *first_usage_push_needed);
/* True if the user may no longer carry traffic (disabled, expired, or over its traffic quota). */
bool                    userRuntimeShouldClose(User *user, uint64_t now_ms);

void userMarkFirstUsage(User *user, uint64_t now_ms);
void userAddTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes);
void userAddSpeed(User *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec);
void userAddConnection(User *user, bool inbound);
void userRemoveConnection(User *user, bool inbound);
void userSetIpCount(User *user, uint64_t ips);
void userSetDeviceCount(User *user, uint64_t devices);
void userSetClientViewExpiry(User *user, uint64_t expires_at_ms, bool valid);
void userGetTimeInfo(User *user, user_time_info_t *timeinfo);
void userGetStats(User *user, user_stat_t *stats);

user_stat_t userStatsDiff(User *base, User *current);
