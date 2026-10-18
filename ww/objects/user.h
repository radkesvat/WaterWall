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
#include "utils/uuid.h"
#include "wcrypto.h"
#include "wmutex.h"

#define USER_NO_LIMIT                        0ULL
#define USER_NO_EXPIRY                       0ULL
#define USER_DEFAULT_RECORD_STAT_INTERVAL_MS 120000
#define USER_WIREGUARD_PUBLICKEY_SIZE        32U
#define USER_WIREGUARD_ALLOWED_IPS_MAX_TEXT  64U

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

/* Owned, credential-free projections. Copy helpers never block behind writers.
 * A zero deadline disables the monotonic deadline check. Non-OK results leave
 * output zeroed; full-detail string storage is released by its destroy helper.
 * Copy output storage must not contain a previous, undestroyed owned detail. */
#define USER_PUBLIC_NAME_PREVIEW_MAX 256U
#define USER_PUBLIC_PAGE_MAX         100U

typedef enum user_public_result_e
{
    kUserPublicOk = 0,
    kUserPublicBusy,
    kUserPublicTimeout,
    kUserPublicNotFound,
    kUserPublicOutOfRange,
    kUserPublicTooLarge,
    kUserPublicInvalidEncoding
} user_public_result_t;

typedef enum user_public_name_state_e
{
    kUserPublicNameComplete = 0,
    kUserPublicNameTruncated,
    kUserPublicNameInvalidEncoding
} user_public_name_state_t;

typedef struct user_public_summary_s
{
    uint64_t                 id, gid;
    bool                     enabled;
    char                     name_preview[USER_PUBLIC_NAME_PREVIEW_MAX + 1U];
    size_t                   name_preview_length;
    user_public_name_state_t name_preview_state;
    user_traffic_limit_t     traffic_limit;
    user_ud_t                usage;
    uint64_t                 expire_at_ms, expire_after_first_usage_ms, first_usage_at_ms;
} user_public_summary_t;

typedef struct user_public_detail_s
{
    uint64_t         id, gid;
    bool             enabled;
    char            *name, *email, *notes, *wireguard_allowed_ips;
    uint64_t         record_stat_interval_ms;
    user_limit_t     limit;
    user_time_info_t timeinfo;
    user_ud_t        usage;
    /* Sum of string allocation sizes, including the four terminating NULs. */
    size_t owned_string_bytes;
} user_public_detail_t;

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
    uint8_t type;      // address family discriminator (0 == none)
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
 * Opaque adaptive index over the active-IP array. For users with only a few
 * distinct active source IPs the dense ip_usages[] array is scanned directly and
 * no index is allocated; once the distinct-IP count crosses a promotion
 * threshold, this hash index maps each user_ip_key_t to its array slot for
 * average-O(1) lookup. Implemented in user.c.
 */
typedef struct user_ip_index_s user_ip_index_t;

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
    /* Optional; NULL until the distinct-IP set is large enough to promote. */
    user_ip_index_t *ip_index;
    bool             first_usage_push_requested;
} user_runtime_stat_t;

/* Client-only accounting clock and elapsed age. Guarded by user_s.lock;
 * never persisted or included in generic copies. Zero is a valid local origin. */
typedef struct user_client_time_s
{
    uint64_t accounting_anchor_ms, local_anchor_ms;
    uint64_t first_local_ms, first_report_ms;
    uint64_t age_ms, age_sample_ms, future_origin_ms;
    uint64_t absolute_config_ms, absolute_deadline_ms;
    bool     clock_valid, observed, observation_acked, age_valid, future_valid;
    bool     absolute_expired;
} user_client_time_t;

/* A coherent, owned value snapshot; no borrowed pointers or runtime resources. */
typedef struct user_accounting_snapshot_s
{
    uint64_t  id;
    user_ud_t traffic;
    uint64_t  first_usage_at_ms;
    bool      observation_pending;
} user_accounting_snapshot_t;

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
    char *wireguard_allowed_ips;

    uint64_t id;
    hash_t   gid;
    bool     enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    /*
     * Runtime-only projection of account expiry policy and retained local age. When valid,
     * expiry checks compare against this local-clock deadline instead of the
     * persisted server-clock timeinfo fields. Never serialized or copied.
     */
    uint64_t client_view_expires_at_ms;
    bool     client_view_expiry_valid;
    bool               client_view_expired;
    user_client_time_t client_time;
    int      record_stat_interval_ms;

    ip_addr_t wireguard_allowed_ip;
    ip_addr_t wireguard_allowed_mask;
    uint64_t  wireguard_allowed_ip_count;
    uint8_t   wireguard_allowed_ip_family;
    uint8_t   wireguard_allowed_ip_prefix;
    bool      wireguard_allowed_ips_valid;

    user_stat_t stats;

    user_runtime_stat_t runtime;

    /*
     * These hashes are laid out for 32-byte operations, but the field attributes
     * only help if the containing user_t object itself is 32-byte aligned.
     * users_t-owned users satisfy that through aligned block allocation; callers
     * with standalone/stack users must not use strict aligned helpers unless
     * they also provide aligned storage.
     */
    hash_t                                         hash_pass;
    uint8_t                                        sha_alignment_padding[8];
    MSVC_ATTR_ALIGNED_32 sha224_hash_t sha224_pass GNU_ATTR_ALIGNED_32;
    uint8_t                                        sha224_pass_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
    MSVC_ATTR_ALIGNED_32 sha256_hash_t sha256_pass GNU_ATTR_ALIGNED_32;
    uint8_t                                        uuid_pass[kWwUuidBytesLen];
    uint8_t                                        wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];

    bool sha224_pass_valid;
    bool sha256_pass_valid;
    bool uuid_pass_valid;
    bool wireguard_publickey_valid;
};

bool userCreate(User *user, const char *password);
bool userCreateFromJson(User *user, const cJSON *user_json);
/* Standalone/deep-copy helpers. For users_t-owned users, prefer usersAddUser()/usersUpdateUser(). */
bool userCopy(User *dest, const User *src);
void userDestroy(User *user);

user_public_result_t userCopyPublicSummary(const user_t *user, uint64_t deadline_ms, user_public_summary_t *out);
user_public_result_t userCopyPublicDetail(const user_t *user, size_t max_string_bytes, uint64_t deadline_ms,
                                          user_public_detail_t *out);
void                 userPublicDetailDestroy(user_public_detail_t *detail);

/*
 * Runtime enforcement-state lifecycle helpers. They own both the active-IP array
 * and the optional adaptive index, so every path that tears down or relocates
 * runtime state (userDestroy(), users_t runtime migration) routes through them
 * and cannot leak or double-free the adaptive index. Callers must hold the
 * relevant user's stats_lock (or otherwise guarantee exclusive access).
 */
void userRuntimeStateClear(user_runtime_stat_t *runtime);
void userRuntimeStateMove(user_runtime_stat_t *dest, user_runtime_stat_t *src);

cJSON *userToJson(User *user);

/*
 * Parses a single WireGuard AllowedIPs CIDR. NULL/empty input is valid and
 * means "not configured"; in that case valid_out is false and normalized_out
 * receives an allocated empty string when requested. normalized_out is owned by
 * the caller and must be released with memoryFree().
 */
bool userWireGuardAllowedIpsParse(const char *value, char **normalized_out, ip_addr_t *ip_out, ip_addr_t *mask_out,
                                  uint8_t *family_out, uint8_t *prefix_out, uint64_t *count_out, bool *valid_out);
bool userWireGuardAllowedIpsStringValid(const char *value);
bool userSetWireGuardAllowedIps(User *user, const char *value);

bool userChangePassword(User *user, const char *password);
/* Compatibility alias for userChangePassword(); prefer usersChangePassword() for database-owned users. */
bool userSetPassword(User *user, const char *password);
/*
 * Exact single-user plaintext check: compares the supplied password against this
 * one user's stored plaintext and derives no password hashes. It is the
 * authoritative, collision-safe verifier a caller runs after selecting a
 * candidate through the SHA-256 lookup table, so a hypothetical SHA-256
 * collision fails closed. It does not consult any collection or hash map.
 */
bool userPasswordMatches(User *user, const char *password);
/*
 * Cold-path full derived-data validation: recomputes SHA-224/SHA-256, the
 * UUID form, and the WireGuard public key from the stored plaintext and checks
 * that all persisted derived credentials agree. Deliberately expensive; used
 * during load, validation, and diagnostics, not on the authentication hot path.
 */
bool userPasswordDataValid(User *user);

void     userSetEnabled(User *user, bool enabled);
bool     userIsEnabled(User *user);
uint64_t userGetId(User *user);
void     userSetId(User *user, uint64_t id);
bool     userIsDisabled(User *user);
bool     userIsExpired(User *user, uint64_t now_ms);
bool     userIsActive(User *user, uint64_t now_ms);
bool     userIsTrafficLimited(User *user);
bool     userHasReachedTrafficLimit(User *user);
bool     userHasReachedBandwidthLimit(User *user);
bool     userHasReachedLimit(User *user);

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
 * With an installed client clock, captures first nonzero traffic and enforces
 * its local duration in the same user-then-stats write transaction. The event
 * clock is sampled after locking; now_ms remains the generic/server fallback.
 * The optional notification does not own or reset the observation.
 */
bool userAccountTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                        bool *first_usage_push_needed);
/* True if the user may no longer carry traffic (disabled, expired, or over its traffic quota). */
bool userRuntimeShouldClose(User *user, uint64_t now_ms);

void userMarkFirstUsage(User *user, uint64_t now_ms);
/* Merge an authenticated accounting observation; unlike MarkFirstUsage, keeps
 * the earliest nonzero instant. The caller clamps future producer estimates. */
void userMergeFirstUsage(User *user, uint64_t first_usage_at_ms);
void userInstallClientClock(User *user, uint64_t server_time_ms, uint64_t accounting_time_ms, uint64_t received_at_ms);
void userGetAccountingSnapshot(User *user, user_accounting_snapshot_t *snapshot);
void userAcknowledgeObservation(User *user, uint64_t first_usage_at_ms);
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
