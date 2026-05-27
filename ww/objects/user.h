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

#include "wcrypto.h" 
#include "cJSON.h"


#define USER_NO_LIMIT 0ULL
#define USER_NO_EXPIRY 0ULL
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

typedef struct user_s User;
typedef User          user_t;
typedef struct user_private_s user_private_t;

struct user_s
{
    wrwlock_t lock;
    wrwlock_t stats_lock;
    bool      initialized;

    /*
     * Private implementation state. The struct stays visible for historical
     * Waterwall APIs, but sync metadata must not be readable or writable by
     * callers and is not loaded from JSON.
     */
    user_private_t *private_state;

    char *name;
    char *password;
    char *email;
    char *notes;

    hash_t gid;
    bool   enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    int              record_stat_interval_ms;

    user_stat_t stats;

    hash_t        hash_pass;
    sha224_hash_t sha224_pass;
    sha256_hash_t sha256_pass;
    sha384_hash_t sha384_pass;
    sha512_hash_t sha512_pass;

    bool sha224_pass_valid;
    bool sha256_pass_valid;
    bool sha384_pass_valid;
    bool sha512_pass_valid;
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
bool userIsDisabled(User *user);
bool userIsExpired(User *user, uint64_t now_ms);
bool userIsActive(User *user, uint64_t now_ms);
bool userIsTrafficLimited(User *user);
bool userHasReachedTrafficLimit(User *user);
bool userHasReachedBandwidthLimit(User *user);
bool userHasReachedLimit(User *user);

void userMarkFirstUsage(User *user, uint64_t now_ms);
void userAddTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes);
void userAddSpeed(User *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec);
void userAddConnection(User *user, bool inbound);
void userRemoveConnection(User *user, bool inbound);
void userSetIpCount(User *user, uint64_t ips);
void userSetDeviceCount(User *user, uint64_t devices);
void userGetStats(User *user, user_stat_t *stats);

user_stat_t userStatsDiff(User *base, User *current);
