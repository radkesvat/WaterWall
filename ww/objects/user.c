/*
 * User object lifecycle, JSON persistence, and usage accounting helpers.
 */

#include "node_builder/config_lexical.h"
#include "objects/user_index_geometry.h"
#include "objects/user_internal.h"

#include "utils/json_helpers.h"
#include "wsocket.h"
#include "wtime.h"

struct user_bandwidth_waiter_s
{
    uint64_t                 ticket;
    bool                     eligible;
    buffer_budget_cost_t     cost;
    user_bandwidth_waiter_t *next;
};

/* Read only one codepoint. Stop at a terminating NUL even in an invalid
 * sequence, so short malformed strings never cause a read past their end. */
static user_public_result_t userPublicCodepointSize(const unsigned char *text, size_t available, size_t *size_out)
{
    unsigned char first = text[0];
    size_t        size;
    if (first < 0x80U)
    {
        *size_out = 1;
        return kUserPublicOk;
    }
    if (first >= 0xC2U && first <= 0xDFU)
        size = 2;
    else if (first >= 0xE0U && first <= 0xEFU)
        size = 3;
    else if (first >= 0xF0U && first <= 0xF4U)
        size = 4;
    else
        return kUserPublicInvalidEncoding;
    if (size > available)
        return kUserPublicTooLarge;
    for (size_t i = 1; i < size; ++i)
    {
        unsigned char next = text[i];
        if (next < 0x80U || next > 0xBFU ||
            (i == 1 && ((first == 0xE0U && next < 0xA0U) || (first == 0xEDU && next > 0x9FU) ||
                        (first == 0xF0U && next < 0x90U) || (first == 0xF4U && next > 0x8FU))))
            return kUserPublicInvalidEncoding;
    }
    *size_out = size;
    return kUserPublicOk;
}

static user_public_result_t userPublicStringSize(const char *text, size_t allowance, uint64_t deadline_ms,
                                                 size_t *size_out)
{
    size_t offset = 0, next_deadline_check = 0;
    if (text == NULL)
    {
        if (allowance == 0)
            return kUserPublicTooLarge;
        *size_out = 1;
        return kUserPublicOk;
    }
    while (offset < allowance)
    {
        if (offset >= next_deadline_check)
        {
            if (userDeadlineExpired(deadline_ms))
                return kUserPublicTimeout;
            next_deadline_check = offset + 256U;
        }
        if (text[offset] == '\0')
        {
            *size_out = offset + 1U;
            return kUserPublicOk;
        }
        size_t               size;
        user_public_result_t result =
            userPublicCodepointSize((const unsigned char *) text + offset, allowance - offset, &size);
        if (result != kUserPublicOk)
            return result;
        offset += size;
    }
    return kUserPublicTooLarge;
}

static user_public_result_t userPublicNamePreview(const char *name, uint64_t deadline_ms, user_public_summary_t *out)
{
    if (name == NULL)
        return kUserPublicOk;
    size_t offset = 0;
    while (offset < USER_PUBLIC_NAME_PREVIEW_MAX && name[offset] != '\0')
    {
        if (userDeadlineExpired(deadline_ms))
            return kUserPublicTimeout;
        size_t               size;
        user_public_result_t result = userPublicCodepointSize((const unsigned char *) name + offset, 4, &size);
        if (result != kUserPublicOk)
        {
            out->name_preview_state = kUserPublicNameInvalidEncoding;
            return kUserPublicOk;
        }
        if (size > USER_PUBLIC_NAME_PREVIEW_MAX - offset)
        {
            out->name_preview_state = kUserPublicNameTruncated;
            break;
        }
        offset += size;
    }
    if (offset == USER_PUBLIC_NAME_PREVIEW_MAX && name[offset] != '\0')
        out->name_preview_state = kUserPublicNameTruncated;
    memoryCopy(out->name_preview, name, offset);
    out->name_preview[offset] = '\0';
    out->name_preview_length  = offset;
    return kUserPublicOk;
}

static user_public_result_t userPublicAcquire(const user_t *user, uint64_t deadline_ms)
{
    if (userDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &user->lock))
        return kUserPublicBusy;
    if (! rwlockTryReadLock((wrwlock_t *) &user->stats_lock))
    {
        rwlockReadUnlock((wrwlock_t *) &user->lock);
        return kUserPublicBusy;
    }
    return kUserPublicOk;
}

static void userPublicRelease(const user_t *user)
{
    rwlockReadUnlock((wrwlock_t *) &user->stats_lock);
    rwlockReadUnlock((wrwlock_t *) &user->lock);
}

user_public_result_t userCopyPublicSummary(const user_t *user, uint64_t deadline_ms, user_public_summary_t *out)
{
    assert(user != NULL && user->initialized && out != NULL);
    memoryZero(out, sizeof(*out));
    user_public_result_t result = userPublicAcquire(user, deadline_ms);
    if (result != kUserPublicOk)
        return result;
    out->id                          = user->id;
    out->gid                         = user->gid;
    out->enabled                     = user->enabled;
    out->traffic_limit               = user->limit.traffic;
    out->usage                       = user->stats.traffic;
    out->expire_at_ms                = user->timeinfo.expire_at_ms;
    out->expire_after_first_usage_ms = user->timeinfo.expire_after_first_usage_ms;
    out->first_usage_at_ms           = user->timeinfo.first_usage_at_ms;
    result                           = userPublicNamePreview(user->name, deadline_ms, out);
    if (result == kUserPublicOk && userDeadlineExpired(deadline_ms))
        result = kUserPublicTimeout;
    userPublicRelease(user);
    if (result != kUserPublicOk)
        memoryZero(out, sizeof(*out));
    return result;
}

void userPublicDetailDestroy(user_public_detail_t *detail)
{
    assert(detail != NULL);
    memoryFree(detail->name);
    memoryFree(detail->email);
    memoryFree(detail->notes);
    memoryFree(detail->wireguard_allowed_ips);
    memoryZero(detail, sizeof(*detail));
}

user_public_result_t userCopyPublicDetail(const user_t *user, size_t max_string_bytes, uint64_t deadline_ms,
                                          user_public_detail_t *out)
{
    assert(user != NULL && user->initialized && out != NULL);
    memoryZero(out, sizeof(*out));
    user_public_result_t result = userPublicAcquire(user, deadline_ms);
    if (result != kUserPublicOk)
        return result;

    const char *strings[] = {user->name, user->email, user->notes, user->wireguard_allowed_ips};
    size_t      sizes[4];
    size_t      total = 0;
    for (size_t i = 0; i < 4; ++i)
    {
        result = userPublicStringSize(strings[i], max_string_bytes - total, deadline_ms, &sizes[i]);
        if (result != kUserPublicOk)
            goto done;
        total += sizes[i];
    }
    if (userDeadlineExpired(deadline_ms))
    {
        result = kUserPublicTimeout;
        goto done;
    }
    out->id                      = user->id;
    out->gid                     = user->gid;
    out->enabled                 = user->enabled;
    out->record_stat_interval_ms = (uint64_t) user->record_stat_interval_ms;
    out->limit                   = user->limit;
    out->timeinfo                = user->timeinfo;
    out->usage                   = user->stats.traffic;
    out->owned_string_bytes      = total;
    char **destinations[]        = {&out->name, &out->email, &out->notes, &out->wireguard_allowed_ips};
    for (size_t i = 0; i < 4; ++i)
    {
        if (userDeadlineExpired(deadline_ms))
        {
            result = kUserPublicTimeout;
            goto done;
        }
        *destinations[i] = memoryAllocate(sizes[i]);
        memoryCopy(*destinations[i], strings[i] != NULL ? strings[i] : "", sizes[i]);
    }
    if (userDeadlineExpired(deadline_ms))
        result = kUserPublicTimeout;
done:
    userPublicRelease(user);
    if (result != kUserPublicOk)
        userPublicDetailDestroy(out);
    return result;
}

_Static_assert(offsetof(user_t, sha224_pass) % 32U == 0, "user_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(user_t, sha256_pass) % 32U == 0, "user_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(user_t) >= 32U, "user_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(user_t) % 32U == 0, "user_t storage size must be a 32-byte multiple");

static bool userStringIsEmpty(const char *value)
{
    return value == NULL || value[0] == '\0';
}

static bool userObjectIsInitialized(const User *user)
{
    return user != NULL && user->initialized;
}

static void userStringDuplicate(char **dest, const char *value)
{
    *dest = stringDuplicate(value != NULL ? value : "");
}

static void userReplaceString(char **dest, const char *value)
{
    char *copy = stringDuplicate(value != NULL ? value : "");
    memoryFree(*dest);
    *dest = copy;
}

static size_t userJsonEscapedByteCost(unsigned char c)
{
    return c == '"' || c == '\\'                                           ? 2U
           : c >= 0x20U                                                    ? 1U
           : c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t' ? 2U
                                                                           : 6U;
}

user_export_string_measure_t userMeasureExportString(const char *text)
{
    user_export_string_measure_t measure = {0};
    if (text == NULL)
        return measure;
    size_t length = 0;
    while (text[length] != '\0')
    {
        size_t cost = userJsonEscapedByteCost((unsigned char) text[length]);
        if (cost > SIZE_MAX - measure.escaped_bytes)
        {
            measure.result = kUserPublicTooLarge;
            return measure;
        }
        measure.escaped_bytes += cost;
        ++length;
    }
    if (! configLexicalCheckEncodingQuiet(text, length))
        measure.result = kUserPublicInvalidEncoding;
    return measure;
}

static void userFreePassword(char *password)
{
    if (UNLIKELY(password == NULL))
    {
        return;
    }

    memorySecureZero(password, stringLength(password));
    memoryFree(password);
}

static void userDestroyStrings(User *user)
{
    memoryFree(user->name);
    userFreePassword(user->password);
    memoryFree(user->email);
    memoryFree(user->notes);
    memoryFree(user->wireguard_allowed_ips);

    user->name                  = NULL;
    user->password              = NULL;
    user->email                 = NULL;
    user->notes                 = NULL;
    user->wireguard_allowed_ips = NULL;
}

static bool userParsePrefixLength(const char *text, uint8_t max_prefix, uint8_t *prefix_out)
{
    uint32_t value = 0;

    if (UNLIKELY(text == NULL || text[0] == '\0' || prefix_out == NULL))
    {
        return false;
    }

    for (const char *p = text; *p != '\0'; ++p)
    {
        if (UNLIKELY(*p < '0' || *p > '9'))
        {
            return false;
        }
        value = (value * 10U) + (uint32_t) (*p - '0');
        if (UNLIKELY(value > max_prefix))
        {
            return false;
        }
    }

    *prefix_out = (uint8_t) value;
    return true;
}

static void userBuildIpv4Mask(uint8_t prefix, ip_addr_t *mask)
{
    const uint32_t mask_value = prefix == 0U ? 0U : (0xFFFFFFFFU << (32U - prefix));

    mask->type = IPADDR_TYPE_V4;
    IP4_ADDR(&mask->u_addr.ip4,
             (mask_value >> 24U) & 0xFFU,
             (mask_value >> 16U) & 0xFFU,
             (mask_value >> 8U) & 0xFFU,
             mask_value & 0xFFU);
}

static void userBuildIpv6Mask(uint8_t prefix, ip_addr_t *mask)
{
    mask->type = IPADDR_TYPE_V6;
    memoryZero(&mask->u_addr.ip6.addr, sizeof(mask->u_addr.ip6.addr));

    for (uint8_t i = 0; i < prefix / 32U; ++i)
    {
        mask->u_addr.ip6.addr[i] = 0xFFFFFFFFU;
    }

    const uint8_t remaining_bits = prefix % 32U;
    if (remaining_bits > 0U)
    {
        mask->u_addr.ip6.addr[prefix / 32U] = htonl(0xFFFFFFFFU << (32U - remaining_bits));
    }
}

static void userNormalizeIpWithMask(ip_addr_t *ip, const ip_addr_t *mask)
{
    if (ip->type == IPADDR_TYPE_V4)
    {
        ip->u_addr.ip4.addr &= mask->u_addr.ip4.addr;
        return;
    }

    if (ip->type == IPADDR_TYPE_V6)
    {
        for (size_t i = 0; i < 4U; ++i)
        {
            ip->u_addr.ip6.addr[i] &= mask->u_addr.ip6.addr[i];
        }
    }
}

static uint64_t userWireGuardAllowedIpCount(uint8_t family, uint8_t prefix)
{
    if (family == 4U)
    {
        return 1ULL << (32U - prefix);
    }

    const uint8_t host_bits = (uint8_t) (128U - prefix);
    if (host_bits >= 64U)
    {
        return UINT64_MAX;
    }
    return 1ULL << host_bits;
}

static bool userDottedIpv4TailValid(const char *text)
{
    if (strchr(text, '.') == NULL)
        return true;

    /* Native inet_pton() implementations differ on leading-zero octets. Apply
     * the same dotted-decimal rules to IPv4 addresses and IPv6 dotted tails. */
    const char *tail = strrchr(text, ':');
    tail             = tail != NULL ? tail + 1 : text;
    for (unsigned int octet = 0; octet < 4U; ++octet)
    {
        if (*tail < '0' || *tail > '9' || (*tail == '0' && tail[1] >= '0' && tail[1] <= '9'))
            return false;
        unsigned int value = 0;
        do
        {
            value = value * 10U + (unsigned int) (*tail++ - '0');
            if (value > 255U)
                return false;
        } while (*tail >= '0' && *tail <= '9');
        if (octet == 3U)
            return *tail == '\0';
        if (*tail != '.')
            return false;
        ++tail;
    }
    return false;
}

bool userWireGuardAllowedIpsParse(const char *value, char **normalized_out, ip_addr_t *ip_out, ip_addr_t *mask_out,
                                  uint8_t *family_out, uint8_t *prefix_out, uint64_t *count_out, bool *valid_out)
{
    char     *compact = NULL;
    char     *slash;
    char      ip_text[48];
    uint8_t   prefix = 0;
    uint8_t   family = 0;
    ip_addr_t ip;
    ip_addr_t mask = {0};
    char      normalized[USER_WIREGUARD_ALLOWED_IPS_MAX_TEXT];

    if (normalized_out != NULL)
    {
        *normalized_out = NULL;
    }
    if (ip_out != NULL)
    {
        memoryZero(ip_out, sizeof(*ip_out));
    }
    if (mask_out != NULL)
    {
        memoryZero(mask_out, sizeof(*mask_out));
    }
    if (family_out != NULL)
    {
        *family_out = 0;
    }
    if (prefix_out != NULL)
    {
        *prefix_out = 0;
    }
    if (count_out != NULL)
    {
        *count_out = 0;
    }
    if (valid_out != NULL)
    {
        *valid_out = false;
    }

    if (value == NULL || value[0] == '\0')
    {
        if (normalized_out != NULL)
        {
            *normalized_out = stringDuplicate("");
            return true;
        }
        return true;
    }
    if (UNLIKELY(stringChr(value, ',') != NULL))
    {
        return false;
    }

    const char *begin = value;
    while (isspace((unsigned char) *begin))
        ++begin;
    const char *end = begin + strlen(begin);
    while (end > begin && isspace((unsigned char) end[-1]))
        --end;
    const size_t length = (size_t) (end - begin);
    compact             = memoryAllocate(length + 1U);
    memoryCopy(compact, begin, length);
    compact[length] = '\0';
    if (compact[0] == '\0')
    {
        if (normalized_out != NULL)
        {
            *normalized_out = stringDuplicate("");
            memoryFree(compact);
            return true;
        }
        memoryFree(compact);
        return true;
    }

    slash = stringChr(compact, '/');
    if (UNLIKELY(slash == NULL || slash == compact || slash[1] == '\0' || stringChr(slash + 1, '/') != NULL))
    {
        memoryFree(compact);
        return false;
    }

    const size_t ip_len = (size_t) (slash - compact);
    if (UNLIKELY(ip_len >= sizeof(ip_text)))
    {
        memoryFree(compact);
        return false;
    }

    memoryCopy(ip_text, compact, ip_len);
    ip_text[ip_len] = '\0';

    if (! userDottedIpv4TailValid(ip_text))
    {
        memoryFree(compact);
        return false;
    }

#ifdef OS_WIN
    WSAInit();
#endif
    struct in_addr ip4;
    if (inet_pton(AF_INET, ip_text, &ip4) == 1)
    {
        if (UNLIKELY(! userParsePrefixLength(slash + 1, 32U, &prefix)))
        {
            memoryFree(compact);
            return false;
        }
        memoryZero(&ip, sizeof(ip));
        ip.type = IPADDR_TYPE_V4;
        memoryCopy(&ip.u_addr.ip4.addr, &ip4, sizeof(ip4));
        userBuildIpv4Mask(prefix, &mask);
        family = 4U;
    }
    else
    {
        struct in6_addr ip6;
        if (UNLIKELY(inet_pton(AF_INET6, ip_text, &ip6) != 1 || ! userParsePrefixLength(slash + 1, 128U, &prefix)))
        {
            memoryFree(compact);
            return false;
        }
        memoryZero(&ip, sizeof(ip));
        ip.type = IPADDR_TYPE_V6;
        memoryCopy(ip.u_addr.ip6.addr, &ip6, sizeof(ip6));
        userBuildIpv6Mask(prefix, &mask);
        family = 6U;
    }

    memoryFree(compact);
    userNormalizeIpWithMask(&ip, &mask);

    const char *ip_string = ipAddrNetworkToAddress(&ip);
    if (UNLIKELY(ip_string == NULL))
    {
        return false;
    }

    const int written = snprintf(normalized, sizeof(normalized), "%s/%u", ip_string, (unsigned int) prefix);
    if (UNLIKELY(written <= 0 || (size_t) written >= sizeof(normalized)))
    {
        return false;
    }

    if (normalized_out != NULL)
    {
        *normalized_out = stringDuplicate(normalized);
    }
    if (ip_out != NULL)
    {
        *ip_out = ip;
    }
    if (mask_out != NULL)
    {
        *mask_out = mask;
    }
    if (family_out != NULL)
    {
        *family_out = family;
    }
    if (prefix_out != NULL)
    {
        *prefix_out = prefix;
    }
    if (count_out != NULL)
    {
        *count_out = userWireGuardAllowedIpCount(family, prefix);
    }
    if (valid_out != NULL)
    {
        *valid_out = true;
    }
    return true;
}

bool userWireGuardAllowedIpsStringValid(const char *value)
{
    return userWireGuardAllowedIpsParse(value, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

bool userSetWireGuardAllowedIps(User *user, const char *value)
{
    char     *normalized = NULL;
    ip_addr_t ip;
    ip_addr_t mask;
    uint8_t   family = 0;
    uint8_t   prefix = 0;
    uint64_t  count  = 0;
    bool      valid  = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }
    if (UNLIKELY(! userWireGuardAllowedIpsParse(value, &normalized, &ip, &mask, &family, &prefix, &count, &valid)))
    {
        return false;
    }

    user_export_string_measure_t measurement = userMeasureExportString(normalized);
    rwlockWriteLock(&user->lock);
    memoryFree(user->wireguard_allowed_ips);
    user->wireguard_allowed_ips       = normalized;
    user->export_strings.allowed_ips  = measurement;
    user->wireguard_allowed_ip        = ip;
    user->wireguard_allowed_mask      = mask;
    user->wireguard_allowed_ip_count  = count;
    user->wireguard_allowed_ip_family = family;
    user->wireguard_allowed_ip_prefix = prefix;
    user->wireguard_allowed_ips_valid = valid;
    rwlockWriteUnlock(&user->lock);
    return true;
}

typedef struct user_snapshot_s
{
    char                 *name;
    char                 *email;
    char                 *notes;
    char                 *wireguard_allowed_ips;
    user_export_strings_t export_strings;

    uint64_t id;
    hash_t   gid;
    bool     enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    int              record_stat_interval_ms;

    ip_addr_t wireguard_allowed_ip;
    ip_addr_t wireguard_allowed_mask;
    uint64_t  wireguard_allowed_ip_count;
    uint8_t   wireguard_allowed_ip_family;
    uint8_t   wireguard_allowed_ip_prefix;
    bool      wireguard_allowed_ips_valid;

    user_stat_t stats;

    union {
        user_credential_value_t credentials;
        struct
        {
            USER_CREDENTIAL_VALUE_FIELDS
        };
    };
} user_snapshot_t;

_Static_assert(offsetof(user_snapshot_t, sha224_pass) % 32U == 0,
               "user_snapshot_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(user_snapshot_t, sha256_pass) % 32U == 0,
               "user_snapshot_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(user_snapshot_t) >= 32U, "user_snapshot_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(user_snapshot_t) % 32U == 0, "user_snapshot_t storage size must be a 32-byte multiple");

static void userSnapshotDestroy(user_snapshot_t *snapshot)
{
    if (UNLIKELY(snapshot == NULL))
    {
        return;
    }

    memoryFree(snapshot->name);
    userFreePassword(snapshot->password);
    memoryFree(snapshot->email);
    memoryFree(snapshot->notes);
    memoryFree(snapshot->wireguard_allowed_ips);
    memorySecureZero(&snapshot->sha224_pass, sizeof(snapshot->sha224_pass));
    memorySecureZero(&snapshot->sha256_pass, sizeof(snapshot->sha256_pass));
    memorySecureZero(snapshot->uuid_pass, sizeof(snapshot->uuid_pass));
    memoryZero(snapshot->wireguard_publickey, sizeof(snapshot->wireguard_publickey));
    memoryZero(snapshot, sizeof(*snapshot));
}

static bool userSnapshotCreate(user_snapshot_t *snapshot, const User *src)
{
    User *mutable_src = (User *) src;

    if (UNLIKELY(snapshot == NULL || ! userObjectIsInitialized(src)))
    {
        return false;
    }

    memoryZero(snapshot, sizeof(*snapshot));

    rwlockReadLock(&mutable_src->lock);
    rwlockReadLock(&mutable_src->stats_lock);

    snapshot->credentials    = src->credentials;
    snapshot->export_strings = src->export_strings;
    userStringDuplicate(&snapshot->name, src->name);
    userStringDuplicate(&snapshot->password, src->password);
    snapshot->password_length = src->password == NULL ? 0 : stringLength(src->password);
    userStringDuplicate(&snapshot->email, src->email);
    userStringDuplicate(&snapshot->notes, src->notes);
    userStringDuplicate(&snapshot->wireguard_allowed_ips, src->wireguard_allowed_ips);

    snapshot->id                          = src->id;
    snapshot->gid                         = src->gid;
    snapshot->enabled                     = src->enabled;
    snapshot->limit                       = src->limit;
    snapshot->timeinfo                    = src->timeinfo;
    snapshot->record_stat_interval_ms     = src->record_stat_interval_ms;
    snapshot->wireguard_allowed_ip        = src->wireguard_allowed_ip;
    snapshot->wireguard_allowed_mask      = src->wireguard_allowed_mask;
    snapshot->wireguard_allowed_ip_count  = src->wireguard_allowed_ip_count;
    snapshot->wireguard_allowed_ip_family = src->wireguard_allowed_ip_family;
    snapshot->wireguard_allowed_ip_prefix = src->wireguard_allowed_ip_prefix;
    snapshot->wireguard_allowed_ips_valid = src->wireguard_allowed_ips_valid;
    snapshot->stats                       = src->stats;

    rwlockReadUnlock(&mutable_src->stats_lock);
    rwlockReadUnlock(&mutable_src->lock);
    return true;
}

_Static_assert(_Alignof(user_prepared_password_t) >= 32U, "credential staging must be aligned");
_Static_assert(sizeof(user_prepared_password_t) % 32U == 0, "credential staging size must preserve alignment");

bool userPreparePassword(user_prepared_password_t *prepared, const char *password, size_t password_length)
{
    static const uint8_t wireguard_basepoint[USER_WIREGUARD_PUBLICKEY_SIZE] = {9};
    assert(prepared != NULL && password != NULL && password_length != 0);
    memoryZero(prepared, sizeof(*prepared));
    prepared->password = memoryAllocate(password_length + 1U);
    memoryCopy(prepared->password, password, password_length + 1U);
    prepared->password_length = password_length;
    prepared->password_export = userMeasureExportString(prepared->password);
    if (wCryptoSHA224(&prepared->sha224_pass, (const unsigned char *) prepared->password, password_length) !=
        kWCryptoOk)
        goto failure;
    prepared->sha224_pass_valid = true;
    if (wCryptoSHA256(&prepared->sha256_pass, (const unsigned char *) prepared->password, password_length) !=
        kWCryptoOk)
        goto failure;
    prepared->sha256_pass_valid = true;
    if (wCryptoX25519(prepared->wireguard_publickey, prepared->sha256_pass.bytes, wireguard_basepoint) != kWCryptoOk)
        goto failure;
    prepared->wireguard_publickey_valid = true;
    prepared->uuid_pass_valid           = wwUuidParseString(prepared->password, prepared->uuid_pass);
    return true;

failure:
    userFreePreparedPassword(prepared);
    return false;
}

void userFreePreparedPassword(user_prepared_password_t *prepared)
{
    if (prepared == NULL)
        return;
    if (prepared->password != NULL)
    {
        memorySecureZero(prepared->password, prepared->password_length + 1U);
        memoryFree(prepared->password);
    }
    memorySecureZero(prepared, sizeof(*prepared));
}

void userCommitPreparedPasswordLocked(User *user, user_prepared_password_t *prepared, size_t old_password_length)
{
    assert(userObjectIsInitialized(user) && prepared != NULL && prepared->password != NULL);
    if (user->password != NULL)
    {
        memorySecureZero(user->password, old_password_length + 1U);
        memoryFree(user->password);
    }
    memorySecureZero(&user->sha224_pass, sizeof(user->sha224_pass));
    memorySecureZero(&user->sha256_pass, sizeof(user->sha256_pass));
    memorySecureZero(user->uuid_pass, sizeof(user->uuid_pass));
    user->credentials  = *prepared;
    prepared->password = NULL;
}

static const cJSON *userJsonGetItem(const cJSON *json_obj, const char *key)
{
    if (! cJSON_IsObject(json_obj))
    {
        return NULL;
    }
    return cJSON_GetObjectItemCaseSensitive(json_obj, key);
}

static const cJSON *userJsonGetItemAliased(const cJSON *json_obj, const char *primary, const char *fallback)
{
    const cJSON *item = userJsonGetItem(json_obj, primary);
    if (item != NULL)
    {
        return item;
    }
    return userJsonGetItem(json_obj, fallback);
}

static bool userJsonGetRequiredStringAliased(const cJSON *json_obj, const char *primary, const char *fallback,
                                             const char **value)
{
    const cJSON *item = userJsonGetItemAliased(json_obj, primary, fallback);
    if (UNLIKELY(! cJSON_IsString(item) || userStringIsEmpty(item->valuestring)))
    {
        return false;
    }

    *value = item->valuestring;
    return true;
}

static bool userJsonReadOptionalString(const cJSON *json_obj, const char *key, const char **value)
{
    const cJSON *item = userJsonGetItem(json_obj, key);
    if (item == NULL || cJSON_IsNull(item))
    {
        *value = NULL;
        return true;
    }
    if (UNLIKELY(! cJSON_IsString(item) || item->valuestring == NULL))
    {
        return false;
    }

    *value = item->valuestring;
    return true;
}

static bool userJsonReadOptionalBoolAliased(const cJSON *json_obj, const char *primary, const char *fallback,
                                            bool *value)
{
    const cJSON *item = userJsonGetItemAliased(json_obj, primary, fallback);
    if (item == NULL || cJSON_IsNull(item))
    {
        return true;
    }
    if (cJSON_IsString(item) && userStringIsEmpty(item->valuestring))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsBool(item)))
    {
        return false;
    }

    *value = cJSON_IsTrue(item);
    return true;
}

static bool userJsonReadOptionalUint64(const cJSON *json_obj, const char *key, uint64_t *value)
{
    const cJSON *item = userJsonGetItem(json_obj, key);

    /* Absent, null, or an empty-string placeholder all mean "keep the current value". */
    if (item == NULL || cJSON_IsNull(item) || (cJSON_IsString(item) && userStringIsEmpty(item->valuestring)))
    {
        return true;
    }

    return getUint64FromJson(value, item);
}

static bool userJsonReadOptionalUint64Aliased(const cJSON *json_obj, const char *primary, const char *alias,
                                              uint64_t *value)
{
    const char *key = userJsonGetItem(json_obj, primary) != NULL ? primary : alias;
    return userJsonReadOptionalUint64(json_obj, key, value);
}

static bool userJsonReadOptionalInt(const cJSON *json_obj, const char *key, int *value)
{
    uint64_t parsed = (uint64_t) *value;

    if (UNLIKELY(! userJsonReadOptionalUint64(json_obj, key, &parsed)))
    {
        return false;
    }
    if (UNLIKELY(parsed > (uint64_t) INT_MAX))
    {
        return false;
    }

    *value = (int) parsed;
    return true;
}

static bool userJsonReadUd(const cJSON *json_obj, user_ud_t *value)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "u", "up", &value->u) &&
           userJsonReadOptionalUint64Aliased(json_obj, "d", "down", &value->d);
}

static bool userJsonReadLimit(const cJSON *json_obj, user_limit_t *limit)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    const cJSON *traffic   = userJsonGetItem(json_obj, "traffic");
    const cJSON *bandwidth = userJsonGetItem(json_obj, "bandwidth");

    if (traffic != NULL && ! cJSON_IsNull(traffic) &&
        (! cJSON_IsString(traffic) || ! userStringIsEmpty(traffic->valuestring)))
    {
        if (UNLIKELY(! cJSON_IsObject(traffic) ||
                     ! userJsonReadOptionalUint64Aliased(traffic, "u", "up", &limit->traffic.u) ||
                     ! userJsonReadOptionalUint64Aliased(traffic, "d", "down", &limit->traffic.d) ||
                     ! userJsonReadOptionalUint64(traffic, "total", &limit->traffic.total)))
        {
            return false;
        }
    }

    if (UNLIKELY(! userJsonReadUd(bandwidth, &limit->bandwidth)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "ip", "ips", &limit->ips) &&
           userJsonReadOptionalUint64(json_obj, "devices", &limit->devices) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-in", "connections-in", &limit->cons_in) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-out", "connections-out", &limit->cons_out);
}

static bool userJsonReadTimeInfo(const cJSON *json_obj, user_time_info_t *timeinfo)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "created-at-ms", "created_at_ms", &timeinfo->created_at_ms) &&
           userJsonReadOptionalUint64Aliased(
               json_obj, "first-usage-at-ms", "first_usage_at_ms", &timeinfo->first_usage_at_ms) &&
           userJsonReadOptionalUint64Aliased(json_obj, "expire-at-ms", "expires-at-ms", &timeinfo->expire_at_ms) &&
           userJsonReadOptionalUint64Aliased(json_obj,
                                             "expire-after-first-usage-ms",
                                             "expire-after-first-use-ms",
                                             &timeinfo->expire_after_first_usage_ms);
}

static bool userJsonReadStats(const cJSON *json_obj, user_stat_t *stats)
{
    const cJSON *speed   = userJsonGetItem(json_obj, "speed");
    const cJSON *traffic = userJsonGetItem(json_obj, "traffic");

    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "ip", "ips", &stats->ips) &&
           userJsonReadOptionalUint64(json_obj, "devices", &stats->devices) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-in", "connections-in", &stats->cons_in) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-out", "connections-out", &stats->cons_out) &&
           userJsonReadUd(speed, &stats->speed) && userJsonReadUd(traffic, &stats->traffic);
}

/* These helpers construct fresh runtime-cJSON values. Heap exhaustion is fatal;
 * the only branches here omit empty configuration/statistics values. */
static void userJsonAddUdIfNotZero(cJSON *root, const char *key, user_ud_t value)
{
    if (value.u == 0 && value.d == 0)
        return;
    cJSON *json = cJSON_CreateObject();
    if (value.u != 0)
        discard jsonAddUint64ToObject(json, "up", value.u);
    if (value.d != 0)
        discard jsonAddUint64ToObject(json, "down", value.d);
    discard cJSON_AddItemToObject(root, key, json);
}

static void userJsonAddLimitIfNotZero(cJSON *root, const user_limit_t *limit)
{
    if (limit->traffic.u == 0 && limit->traffic.d == 0 && limit->traffic.total == 0 && limit->bandwidth.u == 0 &&
        limit->bandwidth.d == 0 && limit->ips == 0 && limit->devices == 0 && limit->cons_in == 0 &&
        limit->cons_out == 0)
        return;
    cJSON *json = cJSON_CreateObject();
    if (limit->traffic.u != 0 || limit->traffic.d != 0 || limit->traffic.total != 0)
    {
        cJSON *traffic = cJSON_CreateObject();
        if (limit->traffic.u != 0)
            discard jsonAddUint64ToObject(traffic, "up", limit->traffic.u);
        if (limit->traffic.d != 0)
            discard jsonAddUint64ToObject(traffic, "down", limit->traffic.d);
        if (limit->traffic.total != 0)
            discard jsonAddUint64ToObject(traffic, "total", limit->traffic.total);
        discard cJSON_AddItemToObject(json, "traffic", traffic);
    }
    userJsonAddUdIfNotZero(json, "bandwidth", limit->bandwidth);
    if (limit->ips != 0)
        discard jsonAddUint64ToObject(json, "ips", limit->ips);
    if (limit->devices != 0)
        discard jsonAddUint64ToObject(json, "devices", limit->devices);
    if (limit->cons_in != 0)
        discard jsonAddUint64ToObject(json, "connections-in", limit->cons_in);
    if (limit->cons_out != 0)
        discard jsonAddUint64ToObject(json, "connections-out", limit->cons_out);
    discard cJSON_AddItemToObject(root, "limit", json);
}

static void userJsonAddTimeInfo(cJSON *root, const user_time_info_t *timeinfo)
{
    if (timeinfo->created_at_ms == 0 && timeinfo->first_usage_at_ms == 0 && timeinfo->expire_at_ms == 0 &&
        timeinfo->expire_after_first_usage_ms == 0)
        return;
    cJSON *json = cJSON_CreateObject();
    if (timeinfo->created_at_ms != 0)
        discard jsonAddUint64ToObject(json, "created-at-ms", timeinfo->created_at_ms);
    if (timeinfo->first_usage_at_ms != 0)
        discard jsonAddUint64ToObject(json, "first-usage-at-ms", timeinfo->first_usage_at_ms);
    if (timeinfo->expire_at_ms != 0)
        discard jsonAddUint64ToObject(json, "expire-at-ms", timeinfo->expire_at_ms);
    if (timeinfo->expire_after_first_usage_ms != 0)
        discard jsonAddUint64ToObject(json, "expire-after-first-usage-ms", timeinfo->expire_after_first_usage_ms);
    discard cJSON_AddItemToObject(root, "time", json);
}

static void userJsonAddStatsIfNotZero(cJSON *root, const user_stat_t *stats)
{
    if (stats->ips == 0 && stats->devices == 0 && stats->cons_in == 0 && stats->cons_out == 0 &&
        stats->traffic.u == 0 && stats->traffic.d == 0)
        return;
    cJSON *json = cJSON_CreateObject();
    if (stats->ips != 0)
        discard jsonAddUint64ToObject(json, "ips", stats->ips);
    if (stats->devices != 0)
        discard jsonAddUint64ToObject(json, "devices", stats->devices);
    if (stats->cons_in != 0)
        discard jsonAddUint64ToObject(json, "connections-in", stats->cons_in);
    if (stats->cons_out != 0)
        discard jsonAddUint64ToObject(json, "connections-out", stats->cons_out);
    userJsonAddUdIfNotZero(json, "traffic", stats->traffic);
    discard cJSON_AddItemToObject(root, "stats", json);
}

static uint64_t userSaturatingAdd(uint64_t a, uint64_t b)
{
    if (UNLIKELY(UINT64_MAX - a < b))
    {
        return UINT64_MAX;
    }
    return a + b;
}

static uint64_t userSaturatingSub(uint64_t a, uint64_t b)
{
    return a > b ? a - b : 0;
}

static bool userLimitReached(uint64_t limit, uint64_t value)
{
    return limit != USER_NO_LIMIT && value >= limit;
}

/* Expiry computation. Caller must hold at least a read lock on user->lock. */
static bool userExpiredLocked(const User *user, uint64_t now_ms)
{
    if (user->client_view_expiry_valid)
    {
        return user->client_view_expired ||
               (user->client_view_expires_at_ms != 0 && now_ms >= user->client_view_expires_at_ms);
    }

    bool expired = userLimitReached(user->timeinfo.expire_at_ms, now_ms);
    if (! expired && user->timeinfo.expire_after_first_usage_ms != USER_NO_EXPIRY &&
        user->timeinfo.first_usage_at_ms != 0)
    {
        expired =
            now_ms >= userSaturatingAdd(user->timeinfo.first_usage_at_ms, user->timeinfo.expire_after_first_usage_ms);
    }
    return expired;
}

/* Traffic-quota computation. Caller must hold read locks on user->lock and user->stats_lock. */
static bool userTrafficReachedLocked(const User *user)
{
    return userLimitReached(user->limit.traffic.u, user->stats.traffic.u) ||
           userLimitReached(user->limit.traffic.d, user->stats.traffic.d) ||
           userLimitReached(user->limit.traffic.total, userSaturatingAdd(user->stats.traffic.u, user->stats.traffic.d));
}

/* Configuration and stats ownership are held; live reservation gauges are not
 * authentication eligibility. */
static user_admission_result_t userEligibilityLocked(const User *user, uint64_t expiry_now)
{
    return ! user->enabled                       ? kUserAdmissionDisabled
           : userExpiredLocked(user, expiry_now) ? kUserAdmissionExpired
           : userTrafficReachedLocked(user)      ? kUserAdmissionTrafficLimited
                                                 : kUserAdmissionOk;
}

user_admission_result_t userCopyAccess(User *user, uint64_t now_ms, uint64_t *id_out, char **name_out,
                                       char **password_out)
{
    assert(userObjectIsInitialized(user) && (name_out == NULL || *name_out == NULL) &&
           (password_out == NULL || *password_out == NULL));
    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    user_admission_result_t result = userEligibilityLocked(user, now_ms);
    if (id_out != NULL)
        *id_out = user->id;
    if (result == kUserAdmissionOk && user->id != 0)
    {
        if (name_out != NULL && user->name != NULL && user->name[0] != '\0')
            *name_out = stringDuplicate(user->name);
        if (password_out != NULL && user->password != NULL && user->password[0] != '\0')
            *password_out = stringDuplicate(user->password);
    }
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return result;
}

user_admission_result_t userCheckEligibility(User *user, uint64_t now_ms, uint64_t *id_out)
{
    return userCopyAccess(user, now_ms, id_out, NULL, NULL);
}

static bool userIpKeyValid(const user_ip_key_t *ip_key)
{
    return ip_key != NULL && ip_key->type != 0;
}

static bool userIpKeyEqual(const user_ip_key_t *a, const user_ip_key_t *b)
{
    return a->type == b->type && memoryCompare(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

/*
 * Distinct active source IPs at which the linear array scan is replaced by the
 * adaptive hash index. Below this the dense array stays allocation-free; only
 * genuinely large per-user IP sets pay for the map.
 */
enum
{
    kUserIpIndexPromotionThreshold = 32
};

static size_t userIpKeyHash(const user_ip_key_t *key)
{
    uint8_t buffer[1U + sizeof(key->bytes)];
    buffer[0] = key->type;
    memoryCopy(&buffer[1], key->bytes, sizeof(key->bytes));
    return (size_t) calcHashBytes(buffer, sizeof(buffer));
}

#define i_type user_ip_index_map_t // NOLINT
#define i_key  user_ip_key_t       // NOLINT
#define i_val  size_t              // NOLINT
#define i_hash userIpKeyHash       // NOLINT
#define i_eq   userIpKeyEqual      // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

struct user_ip_index_s
{
    user_ip_index_map_t map;
};

static void userIpIndexFree(user_ip_index_t *index)
{
    if (index == NULL)
    {
        return;
    }
    user_ip_index_map_t_drop(&index->map);
    memoryFree(index);
}

void userRuntimeStateClear(user_runtime_stat_t *runtime)
{
    if (runtime == NULL)
    {
        return;
    }
    if (runtime->ip_usages != NULL)
    {
        memoryFree(runtime->ip_usages);
    }
    userIpIndexFree(runtime->ip_index);
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        user_bandwidth_waiter_t *waiter = runtime->bandwidth[direction].head;
        while (waiter != NULL)
        {
            user_bandwidth_waiter_t *next = waiter->next;
            memoryFree(waiter);
            waiter = next;
        }
    }
    memoryZero(runtime, sizeof(*runtime));
}

void userRuntimeStateMove(user_runtime_stat_t *dest, user_runtime_stat_t *src)
{
    if (dest == NULL || src == NULL)
    {
        return;
    }
    if (dest == src)
    {
        /* A self-move must preserve the state; clearing dest first would free the
         * very buffers we would then copy back, losing (and double-freeing) them. */
        return;
    }
    userRuntimeStateClear(dest);
    *dest = *src;
    memoryZero(src, sizeof(*src));
}

/* Builds the adaptive index from the authoritative dense array. Its capacity
 * is validated before the corresponding array entry is admitted. */
static void userRuntimePromoteIpIndexLocked(user_runtime_stat_t *runtime)
{
    user_ip_index_t *index = memoryAllocateZero(sizeof(*index));
    discard          user_ip_index_map_t_reserve(&index->map, (isize) runtime->ip_usage_count);
    for (size_t i = 0; i < runtime->ip_usage_count; ++i)
        discard user_ip_index_map_t_insert(&index->map, runtime->ip_usages[i].key, i);
    runtime->ip_index = index;
}

/* Records that a new IP was appended at new_index: extend the index if present,
 * otherwise promote once the distinct-IP set is large enough. */
static void userRuntimeIpAddedLocked(user_runtime_stat_t *runtime, size_t new_index)
{
    if (runtime->ip_index != NULL)
    {
        discard user_ip_index_map_t_insert(&runtime->ip_index->map, runtime->ip_usages[new_index].key, new_index);
        return;
    }
    if (runtime->ip_usage_count >= (size_t) kUserIpIndexPromotionThreshold)
        userRuntimePromoteIpIndexLocked(runtime);
}

/*
 * Updates the index for a swap-with-last removal: the entry at removed_index was
 * dropped and (unless it was the last) the entry formerly at old_last was moved
 * into removed_index. Frees the index once the set becomes empty.
 */
static void userRuntimeIpRemovedLocked(user_runtime_stat_t *runtime, size_t removed_index,
                                       const user_ip_key_t *removed_key, size_t old_last)
{
    if (runtime->ip_index != NULL)
    {
        user_ip_index_map_t_erase(&runtime->ip_index->map, *removed_key);
        if (removed_index != old_last)
        {
            /* The moved entry now lives at removed_index. */
            user_ip_index_map_t_insert_or_assign(
                &runtime->ip_index->map, runtime->ip_usages[removed_index].key, removed_index);
        }
        if (runtime->ip_usage_count == 0)
        {
            userIpIndexFree(runtime->ip_index);
            runtime->ip_index = NULL;
        }
    }
}

/* Returns the index of ip_key in the runtime tracker, or runtime->ip_usage_count when absent. */
static size_t userRuntimeFindIpLocked(const user_runtime_stat_t *runtime, const user_ip_key_t *ip_key)
{
    if (runtime->ip_index != NULL)
    {
        user_ip_index_map_t_iter it = user_ip_index_map_t_find(&runtime->ip_index->map, *ip_key);
        return it.ref != NULL ? it.ref->second : runtime->ip_usage_count;
    }

    for (size_t i = 0; i < runtime->ip_usage_count; ++i)
    {
        if (userIpKeyEqual(&runtime->ip_usages[i].key, ip_key))
        {
            return i;
        }
    }
    return runtime->ip_usage_count;
}

/* Ensures room for at least one more IP usage entry. Caller holds user->stats_lock. */
static bool userRuntimeReserveIpLocked(user_runtime_stat_t *runtime)
{
    const size_t count = runtime->ip_usage_count;
    /* Insertion can grow an existing hash table by 3/2, so validate that request
     * before admitting a new array entry. This is a geometry refusal, not OOM. */
    if (count >= (size_t) PTRDIFF_MAX / 2U || ! userIndexHashCapacityIsRepresentable(count * 3U / 2U + 2U,
                                                                                     sizeof(user_ip_index_map_t_value),
                                                                                     sizeof(struct hmap_meta)))
        return false;
    if (count < runtime->ip_usage_capacity)
        return true;
    const size_t maximum_capacity = (size_t) PTRDIFF_MAX / sizeof(*runtime->ip_usages);
    if (runtime->ip_usage_capacity > maximum_capacity / 2U)
        return false;
    const size_t     new_capacity = runtime->ip_usage_capacity == 0 ? 4 : runtime->ip_usage_capacity * 2U;
    user_ip_usage_t *grown        = memoryReAllocate(runtime->ip_usages, new_capacity * sizeof(*grown));

    runtime->ip_usages         = grown;
    runtime->ip_usage_capacity = new_capacity;
    return true;
}

bool userCreate(User *user, const char *password)
{
    if (UNLIKELY(user == NULL || userStringIsEmpty(password)))
    {
        return false;
    }

    discard userExportFixedOverhead();
    memoryZero(user, sizeof(*user));
    if (UNLIKELY(! rwlockTryInit(&user->lock)))
    {
        return false;
    }
    if (UNLIKELY(! rwlockTryInit(&user->stats_lock)))
    {
        rwlockDestroy(&user->lock);
        return false;
    }

    user->initialized = true;

    user->enabled                 = true;
    user->record_stat_interval_ms = USER_DEFAULT_RECORD_STAT_INTERVAL_MS;
    user->timeinfo.created_at_ms  = getTimeOfDayMS();

    userStringDuplicate(&user->name, "");
    userStringDuplicate(&user->email, "");
    userStringDuplicate(&user->notes, "");
    userStringDuplicate(&user->wireguard_allowed_ips, "");
    if (UNLIKELY(! userChangePassword(user, password)))
    {
        userDestroy(user);
        return false;
    }

    return true;
}

static bool userInstallOwnedSnapshot(User *dest, user_snapshot_t *snapshot)
{
    memoryZero(dest, sizeof(*dest));
    if (UNLIKELY(! rwlockTryInit(&dest->lock)))
    {
        return false;
    }
    if (UNLIKELY(! rwlockTryInit(&dest->stats_lock)))
    {
        rwlockDestroy(&dest->lock);
        return false;
    }

    dest->initialized = true;

    dest->name                  = snapshot->name;
    dest->password              = snapshot->password;
    dest->password_length       = snapshot->password_length;
    dest->email                 = snapshot->email;
    dest->notes                 = snapshot->notes;
    dest->wireguard_allowed_ips = snapshot->wireguard_allowed_ips;
    dest->export_strings        = snapshot->export_strings;

    dest->id                          = snapshot->id;
    dest->gid                         = snapshot->gid;
    dest->enabled                     = snapshot->enabled;
    dest->limit                       = snapshot->limit;
    dest->timeinfo                    = snapshot->timeinfo;
    dest->record_stat_interval_ms     = snapshot->record_stat_interval_ms;
    dest->wireguard_allowed_ip        = snapshot->wireguard_allowed_ip;
    dest->wireguard_allowed_mask      = snapshot->wireguard_allowed_mask;
    dest->wireguard_allowed_ip_count  = snapshot->wireguard_allowed_ip_count;
    dest->wireguard_allowed_ip_family = snapshot->wireguard_allowed_ip_family;
    dest->wireguard_allowed_ip_prefix = snapshot->wireguard_allowed_ip_prefix;
    dest->wireguard_allowed_ips_valid = snapshot->wireguard_allowed_ips_valid;
    dest->stats                       = snapshot->stats;
    dest->credentials                 = snapshot->credentials;
    snapshot->name = snapshot->password = snapshot->email = snapshot->notes = snapshot->wireguard_allowed_ips = NULL;
    return true;
}

bool userCopy(User *dest, const User *src)
{
    if (dest == NULL || src == NULL)
        return false;
    user_snapshot_t snapshot;
    if (! userSnapshotCreate(&snapshot, src))
        return false;
    bool copied = userInstallOwnedSnapshot(dest, &snapshot);
    userSnapshotDestroy(&snapshot);
    return copied;
}

bool userMoveOwnedValue(User *dest, User *source)
{
    assert(dest != NULL && userObjectIsInitialized(source) && dest != source);
    user_snapshot_t snapshot             = {0};
    snapshot.name                        = source->name;
    snapshot.email                       = source->email;
    snapshot.notes                       = source->notes;
    snapshot.wireguard_allowed_ips       = source->wireguard_allowed_ips;
    snapshot.credentials                 = source->credentials;
    snapshot.export_strings              = source->export_strings;
    snapshot.id                          = source->id;
    snapshot.gid                         = source->gid;
    snapshot.enabled                     = source->enabled;
    snapshot.limit                       = source->limit;
    snapshot.timeinfo                    = source->timeinfo;
    snapshot.stats                       = source->stats;
    snapshot.record_stat_interval_ms     = source->record_stat_interval_ms;
    snapshot.wireguard_allowed_ip        = source->wireguard_allowed_ip;
    snapshot.wireguard_allowed_mask      = source->wireguard_allowed_mask;
    snapshot.wireguard_allowed_ip_count  = source->wireguard_allowed_ip_count;
    snapshot.wireguard_allowed_ip_family = source->wireguard_allowed_ip_family;
    snapshot.wireguard_allowed_ip_prefix = source->wireguard_allowed_ip_prefix;
    snapshot.wireguard_allowed_ips_valid = source->wireguard_allowed_ips_valid;
    if (! userInstallOwnedSnapshot(dest, &snapshot))
    {
        memorySecureZero(&snapshot, sizeof(snapshot));
        return false;
    }
    source->name = source->password = source->email = source->notes = source->wireguard_allowed_ips = NULL;
    source->password_length                                                                         = 0;
    memoryZero(&source->password_export, sizeof(source->password_export));
    memoryZero(&source->export_strings, sizeof(source->export_strings));
    userSnapshotDestroy(&snapshot);
    return true;
}

void userDestroy(User *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized))
    {
        return;
    }

    userDestroyStrings(user);
    userRuntimeStateClear(&user->runtime);
    memorySecureZero(&user->sha224_pass, sizeof(user->sha224_pass));
    memorySecureZero(&user->sha256_pass, sizeof(user->sha256_pass));
    memorySecureZero(user->uuid_pass, sizeof(user->uuid_pass));
    memoryZero(user->wireguard_publickey, sizeof(user->wireguard_publickey));
    memoryZero(&user->limit, sizeof(user->limit));
    memoryZero(&user->timeinfo, sizeof(user->timeinfo));
    memoryZero(&user->wireguard_allowed_ip, sizeof(user->wireguard_allowed_ip));
    memoryZero(&user->wireguard_allowed_mask, sizeof(user->wireguard_allowed_mask));
    memoryZero(&user->stats, sizeof(user->stats));
    user->id                          = 0;
    user->enabled                     = false;
    user->wireguard_allowed_ip_count  = 0;
    user->wireguard_allowed_ip_family = 0;
    user->wireguard_allowed_ip_prefix = 0;
    user->wireguard_allowed_ips_valid = false;

    rwlockDestroy(&user->stats_lock);
    rwlockDestroy(&user->lock);
    memoryZero(user, sizeof(*user));
}

bool userChangePassword(User *user, const char *password)
{
    user_prepared_password_t prepared = {0};
    if (! userObjectIsInitialized(user) || userStringIsEmpty(password))
        return false;
    if (! userPreparePassword(&prepared, password, stringLength(password)))
        return false;
    rwlockWriteLock(&user->lock);
    userCommitPreparedPasswordLocked(user, &prepared, user->password == NULL ? 0 : stringLength(user->password));
    rwlockWriteUnlock(&user->lock);
    userFreePreparedPassword(&prepared);
    return true;
}

bool userSetPassword(User *user, const char *password)
{
    return userChangePassword(user, password);
}

bool userPrepareJsonAllowedIps(const cJSON *json, user_allowed_ip_preparation_t *prepared)
{
    assert(prepared != NULL);
    memoryZero(prepared, sizeof(*prepared));
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, "wireguard-allowed-ips");
    if (item == NULL || cJSON_IsNull(item))
        return true;
    if (! cJSON_IsString(item) || item->valuestring == NULL)
        return false;
    user_parsed_allowed_ip_t *value = &prepared->value;
    return userWireGuardAllowedIpsParse(item->valuestring,
                                        &prepared->text,
                                        &value->wireguard_allowed_ip,
                                        &value->wireguard_allowed_mask,
                                        &value->wireguard_allowed_ip_family,
                                        &value->wireguard_allowed_ip_prefix,
                                        &value->wireguard_allowed_ip_count,
                                        &value->wireguard_allowed_ips_valid);
}

static bool userInstallJsonAllowedIps(User *user, const char *value, user_allowed_ip_preparation_t *prepared)
{
    if (prepared == NULL)
        return value == NULL || userSetWireGuardAllowedIps(user, value);
    if (prepared->text != NULL)
    {
        memoryFree(user->wireguard_allowed_ips);
        user->wireguard_allowed_ips      = prepared->text;
        user->export_strings.allowed_ips = userMeasureExportString(prepared->text);
        prepared->text                   = NULL;
        user->allowed_ip                 = prepared->value;
    }
    return true;
}

user_json_result_t userCreateFromJsonPreparedAllowedIpsResult(User *user, const cJSON *user_json,
                                                              user_allowed_ip_preparation_t *prepared)
{
    const char  *password = NULL;
    const char  *value    = NULL;
    const char  *name     = NULL;
    const char  *email    = NULL;
    const char  *notes    = NULL;
    const cJSON *limit    = NULL;
    const cJSON *timeinfo = NULL;
    const cJSON *stats    = NULL;

    if (UNLIKELY(user == NULL || ! cJSON_IsObject(user_json)))
    {
        return kUserJsonInvalid;
    }
    if (UNLIKELY(! userJsonGetRequiredStringAliased(user_json, "password", "pass", &password)))
    {
        return kUserJsonInvalid;
    }
    if (UNLIKELY(! userCreate(user, password)))
    {
        return kUserJsonResourceFailure;
    }

    if (UNLIKELY(! userJsonReadOptionalString(user_json, "name", &name) ||
                 ! userJsonReadOptionalString(user_json, "email", &email) ||
                 ! userJsonReadOptionalString(user_json, "notes", &notes) ||
                 ! userJsonReadOptionalString(user_json, "wireguard-allowed-ips", &value) ||
                 ! userInstallJsonAllowedIps(user, value, prepared) ||
                 ! userJsonReadOptionalUint64Aliased(user_json, "id", "user-id", &user->id) ||
                 ! userJsonReadOptionalUint64Aliased(user_json, "gid", "group-id", &user->gid) ||
                 ! userJsonReadOptionalBoolAliased(user_json, "enabled", "enable", &user->enabled) ||
                 ! userJsonReadOptionalInt(user_json, "record-stat-interval-ms", &user->record_stat_interval_ms)))
    {
        userDestroy(user);
        return kUserJsonInvalid;
    }

    if (name != NULL)
    {
        userReplaceString(&user->name, name);
        user->export_strings.name = userMeasureExportString(user->name);
    }
    if (email != NULL)
    {
        userReplaceString(&user->email, email);
        user->export_strings.email = userMeasureExportString(user->email);
    }
    if (notes != NULL)
    {
        userReplaceString(&user->notes, notes);
        user->export_strings.notes = userMeasureExportString(user->notes);
    }

    limit    = cJSON_GetObjectItemCaseSensitive(user_json, "limit");
    timeinfo = cJSON_GetObjectItemCaseSensitive(user_json, "time");
    stats    = cJSON_GetObjectItemCaseSensitive(user_json, "stats");

    if (UNLIKELY(! userJsonReadLimit(limit, &user->limit) || ! userJsonReadTimeInfo(timeinfo, &user->timeinfo) ||
                 ! userJsonReadStats(stats, &user->stats)))
    {
        userDestroy(user);
        return kUserJsonInvalid;
    }

    if (UNLIKELY(! userJsonReadOptionalUint64Aliased(
                     user_json, "created-at-ms", "created_at_ms", &user->timeinfo.created_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(
                     user_json, "first-usage-at-ms", "first_usage_at_ms", &user->timeinfo.first_usage_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(
                     user_json, "expire-at-ms", "expires-at-ms", &user->timeinfo.expire_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(user_json,
                                                     "expire-after-first-usage-ms",
                                                     "expire-after-first-use-ms",
                                                     &user->timeinfo.expire_after_first_usage_ms)))
    {
        userDestroy(user);
        return kUserJsonInvalid;
    }

    return kUserJsonOk;
}

bool userCreateFromJsonPreparedAllowedIps(User *user, const cJSON *json, user_allowed_ip_preparation_t *prepared)
{
    return userCreateFromJsonPreparedAllowedIpsResult(user, json, prepared) == kUserJsonOk;
}

user_json_result_t userCreateFromJsonResult(User *user, const cJSON *json)
{
    return userCreateFromJsonPreparedAllowedIpsResult(user, json, NULL);
}

bool userCreateFromJson(User *user, const cJSON *json)
{
    return userCreateFromJsonResult(user, json) == kUserJsonOk;
}

static void userJsonAddExportString(cJSON *json, const char *key, const char *text, bool required, bool placeholders)
{
    if (! required && (text == NULL || text[0] == '\0'))
        return;
    discard cJSON_AddStringToObject(json, key, placeholders ? "" : text);
}

/* Caller holds configuration ownership. Statistics are a coherent copied value. */
static cJSON *userBuildJsonLocked(User *user, const user_stat_t *stats, bool placeholders)
{
    cJSON *json = cJSON_CreateObject();
    userJsonAddExportString(json, "name", user->name, false, placeholders);
    userJsonAddExportString(json, "password", user->password, true, placeholders);
    userJsonAddExportString(json, "email", user->email, false, placeholders);
    userJsonAddExportString(json, "notes", user->notes, false, placeholders);
    userJsonAddExportString(json, "wireguard-allowed-ips", user->wireguard_allowed_ips, false, placeholders);
    if (user->id != 0)
        discard jsonAddUint64ToObject(json, "id", user->id);
    if (user->gid != 0)
        discard jsonAddUint64ToObject(json, "gid", user->gid);
    if (! user->enabled)
        discard cJSON_AddFalseToObject(json, "enabled");
    if (user->record_stat_interval_ms != USER_DEFAULT_RECORD_STAT_INTERVAL_MS)
        discard jsonAddUint64ToObject(json, "record-stat-interval-ms", (uint64_t) user->record_stat_interval_ms);
    userJsonAddTimeInfo(json, &user->timeinfo);
    userJsonAddLimitIfNotZero(json, &user->limit);
    userJsonAddStatsIfNotZero(json, stats);
    return json;
}

size_t userExportFixedOverhead(void)
{
    static atomic_size_t cached   = 0;
    size_t               overhead = atomic_load(&cached);
    if (overhead != 0)
        return overhead;
    /* Nonempty sentinels select every optional string, but placeholders avoid
     * charging their content. UINT64_MAX exercises decimal-string encoding. */
    user_t maximum   = {0};
    char   present[] = "x";
    maximum.name = maximum.password = maximum.email = maximum.notes = maximum.wireguard_allowed_ips = present;
    maximum.id                                                                                      = UINT64_MAX;
    maximum.gid                                                                                     = UINT64_MAX;
    maximum.record_stat_interval_ms                                                                 = -1;
    maximum.limit     = (user_limit_t) {.traffic   = {UINT64_MAX, UINT64_MAX, UINT64_MAX},
                                        .bandwidth = {UINT64_MAX, UINT64_MAX},
                                        .ips       = UINT64_MAX,
                                        .devices   = UINT64_MAX,
                                        .cons_in   = UINT64_MAX,
                                        .cons_out  = UINT64_MAX};
    maximum.timeinfo  = (user_time_info_t) {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
    user_stat_t stats = {.ips      = UINT64_MAX,
                         .devices  = UINT64_MAX,
                         .cons_in  = UINT64_MAX,
                         .cons_out = UINT64_MAX,
                         .traffic  = {UINT64_MAX, UINT64_MAX}};
    cJSON      *json  = userBuildJsonLocked(&maximum, &stats, true);
    char       *text  = cJSON_PrintUnformatted(json);
    overhead          = stringLength(text);
    cJSON_free(text);
    cJSON_Delete(json);
    atomic_store(&cached, overhead);
    return overhead;
}

user_public_result_t userMeasureExportFields(const user_export_strings_t        *strings,
                                             const user_export_string_measure_t *password, size_t limit,
                                             size_t *encoded_size)
{
    assert(strings != NULL && password != NULL && encoded_size != NULL);
    *encoded_size                                = 0;
    const user_export_string_measure_t *fields[] = {
        &strings->name, password, &strings->email, &strings->notes, &strings->allowed_ips};
    size_t size = userExportFixedOverhead();
    if (size > limit)
        return kUserPublicTooLarge;
    for (size_t i = 0; i < ARRAY_SIZE(fields); ++i)
    {
        if (fields[i]->result != kUserPublicOk)
            return fields[i]->result;
        if (fields[i]->escaped_bytes > limit - size)
            return kUserPublicTooLarge;
        size += fields[i]->escaped_bytes;
    }
    *encoded_size = size;
    return kUserPublicOk;
}

user_public_result_t userMeasureExportUpperBound(const user_t *user, size_t *encoded_size)
{
    assert(userObjectIsInitialized(user) && encoded_size != NULL);
    rwlockReadLock((wrwlock_t *) &user->lock);
    user_public_result_t result =
        userMeasureExportFields(&user->export_strings, &user->password_export, SIZE_MAX, encoded_size);
    rwlockReadUnlock((wrwlock_t *) &user->lock);
    return result;
}

cJSON *userToJson(User *user)
{
    if (! userObjectIsInitialized(user))
        return NULL;
    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    user_stat_t stats = user->stats;
    rwlockReadUnlock(&user->stats_lock);
    cJSON *json = userBuildJsonLocked(user, &stats, false);
    rwlockReadUnlock(&user->lock);
    return json;
}

user_public_result_t userCopyFullJsonBounded(User *user, size_t limit, cJSON **out, size_t *encoded_size)
{
    assert(userObjectIsInitialized(user) && out != NULL && encoded_size != NULL);
    *out          = NULL;
    *encoded_size = 0;
    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    user_stat_t stats = user->stats;
    rwlockReadUnlock(&user->stats_lock);
    /* Only fixed-size numeric metadata and empty placeholders are allocated
     * before string admission. No arbitrary row string is copied yet. */
    cJSON *json   = userBuildJsonLocked(user, &stats, true);
    char  *scalar = cJSON_PrintUnformatted(json);
    size_t size   = stringLength(scalar);
    cJSON_free(scalar);
    user_public_result_t result = kUserPublicTooLarge;
    if (size > limit)
        goto done;
    const char *texts[] = {user->name, user->password, user->email, user->notes, user->wireguard_allowed_ips};
    const char *keys[]  = {"name", "password", "email", "notes", "wireguard-allowed-ips"};
    for (size_t i = 0; i < ARRAY_SIZE(texts); ++i)
    {
        const char *text = texts[i];
        if (text == NULL)
        {
            if (i == 1)
            {
                result = kUserPublicInvalidEncoding;
                goto done;
            }
            continue;
        }
        size_t length = 0;
        while (text[length] != '\0')
        {
            unsigned char c    = (unsigned char) text[length];
            size_t        cost = userJsonEscapedByteCost(c);
            if (cost > limit - size)
                goto done;
            size += cost;
            ++length;
        }
        if (! configLexicalCheckEncodingQuiet(text, length))
        {
            result = kUserPublicInvalidEncoding;
            goto done;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(texts); ++i)
    {
        cJSON *field = cJSON_GetObjectItemCaseSensitive(json, keys[i]);
        if (field != NULL)
            discard cJSON_SetValuestring(field, texts[i]);
    }
    *out          = json;
    *encoded_size = size;
    json          = NULL;
    result        = kUserPublicOk;
done:
    cJSON_Delete(json);
    rwlockReadUnlock(&user->lock);
    return result;
}

bool userPasswordMatches(User *user, const char *password)
{
    bool result = false;

    if (UNLIKELY(! userObjectIsInitialized(user) || userStringIsEmpty(password)))
    {
        return false;
    }

    /*
     * Exact single-user plaintext verification. The caller has already selected
     * this candidate through the users_t SHA-256 lookup table, so re-deriving
     * SHA-224/SHA-256 here would only repeat work already implied by the index
     * hit. The authoritative, collision-safe check is the exact byte comparison
     * of the stored plaintext against the supplied plaintext: a hypothetical
     * SHA-256 index collision fails closed because the plaintext will not match.
     */
    rwlockReadLock(&user->lock);
    if (LIKELY(! userStringIsEmpty(user->password)))
    {
        const size_t password_len = stringLength(password);
        result = stringLength(user->password) == password_len && memoryEqual(user->password, password, password_len);
    }
    rwlockReadUnlock(&user->lock);
    return result;
}

bool userPasswordDataValid(User *user)
{
    static const uint8_t wireguard_basepoint[USER_WIREGUARD_PUBLICKEY_SIZE] = {9};
    sha224_hash_t        sha224                                             = {0};
    sha256_hash_t        sha256                                             = {0};
    uint8_t              uuid[kWwUuidBytesLen]                              = {0};
    uint8_t              wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    bool                 result                                             = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    if (! userStringIsEmpty(user->password) && user->sha224_pass_valid && user->sha256_pass_valid)
    {
        result = wCryptoSHA224(&sha224, (const unsigned char *) user->password, stringLength(user->password)) ==
                     kWCryptoOk &&
                 wCryptoSHA256(&sha256, (const unsigned char *) user->password, stringLength(user->password)) ==
                     kWCryptoOk &&
                 memoryEqual(&sha256, &user->sha256_pass, sizeof(sha256)) &&
                 memoryEqual(&sha224, &user->sha224_pass, sizeof(sha224));
        if (result)
        {
            const bool password_is_uuid = wwUuidParseString(user->password, uuid);
            result = password_is_uuid ? user->uuid_pass_valid && memoryEqual(uuid, user->uuid_pass, sizeof(uuid))
                                      : ! user->uuid_pass_valid;
        }
        if (result)
        {
            result = user->wireguard_publickey_valid &&
                     wCryptoX25519(wireguard_publickey, sha256.bytes, wireguard_basepoint) == kWCryptoOk &&
                     memoryEqual(wireguard_publickey, user->wireguard_publickey, sizeof(wireguard_publickey));
        }
    }
    rwlockReadUnlock(&user->lock);

    memorySecureZero(&sha224, sizeof(sha224));
    memorySecureZero(&sha256, sizeof(sha256));
    memorySecureZero(uuid, sizeof(uuid));
    memoryZero(wireguard_publickey, sizeof(wireguard_publickey));
    return result;
}

void userSetEnabled(User *user, bool enabled)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->enabled = enabled;
    rwlockWriteUnlock(&user->lock);
}

bool userIsEnabled(User *user)
{
    bool enabled = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    enabled = user->enabled;
    rwlockReadUnlock(&user->lock);
    return enabled;
}

uint64_t userGetId(User *user)
{
    uint64_t id = 0;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return 0;
    }

    rwlockReadLock(&user->lock);
    id = user->id;
    rwlockReadUnlock(&user->lock);
    return id;
}

void userSetId(User *user, uint64_t id)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->id = id;
    rwlockWriteUnlock(&user->lock);
}

bool userIsDisabled(User *user)
{
    return ! userIsEnabled(user);
}

bool userIsExpired(User *user, uint64_t now_ms)
{
    bool expired = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    expired = userExpiredLocked(user, now_ms);
    rwlockReadUnlock(&user->lock);
    return expired;
}

bool userIsActive(User *user, uint64_t now_ms)
{
    return userIsEnabled(user) && ! userIsExpired(user, now_ms) && ! userHasReachedLimit(user);
}

bool userIsTrafficLimited(User *user)
{
    bool limited = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    limited = user->limit.traffic.u != USER_NO_LIMIT || user->limit.traffic.d != USER_NO_LIMIT ||
              user->limit.traffic.total != USER_NO_LIMIT;
    rwlockReadUnlock(&user->lock);
    return limited;
}

bool userHasReachedTrafficLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached = userTrafficReachedLocked(user);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

bool userHasReachedBandwidthLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached = userLimitReached(user->limit.bandwidth.u, user->stats.speed.u) ||
              userLimitReached(user->limit.bandwidth.d, user->stats.speed.d);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

bool userHasReachedLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached =
        userLimitReached(user->limit.ips, user->stats.ips) ||
        userLimitReached(user->limit.devices, user->stats.devices) ||
        userLimitReached(user->limit.cons_in, user->stats.cons_in) ||
        userLimitReached(user->limit.cons_out, user->stats.cons_out) ||
        userLimitReached(user->limit.traffic.u, user->stats.traffic.u) ||
        userLimitReached(user->limit.traffic.d, user->stats.traffic.d) ||
        userLimitReached(user->limit.traffic.total, userSaturatingAdd(user->stats.traffic.u, user->stats.traffic.d)) ||
        userLimitReached(user->limit.bandwidth.u, user->stats.speed.u) ||
        userLimitReached(user->limit.bandwidth.d, user->stats.speed.d);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

void userMarkFirstUsage(User *user, uint64_t now_ms)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    if (user->timeinfo.first_usage_at_ms == 0)
    {
        user->timeinfo.first_usage_at_ms = now_ms;
    }
    rwlockWriteUnlock(&user->lock);
}

void userMergeFirstUsage(User *user, uint64_t first_usage_at_ms)
{
    assert(userObjectIsInitialized(user) && first_usage_at_ms != 0);
    rwlockWriteLock(&user->lock);
    if (user->timeinfo.first_usage_at_ms == 0 || first_usage_at_ms < user->timeinfo.first_usage_at_ms)
        user->timeinfo.first_usage_at_ms = first_usage_at_ms;
    rwlockWriteUnlock(&user->lock);
}

/* All client time operations hold the user write lock. An older sample adds
 * no elapsed time and never rewinds the age anchor. */
static uint64_t userClientAdvanceAgeLocked(User *user, uint64_t now)
{
    user_client_time_t *time = &user->client_time;
    now                      = max(now, time->age_sample_ms);
    if (time->age_valid)
        time->age_ms = userSaturatingAdd(time->age_ms, userSaturatingSub(now, time->age_sample_ms));
    if (time->future_valid && now >= time->future_origin_ms)
    {
        time->age_ms    = max(time->age_ms, now - time->future_origin_ms);
        time->age_valid = true;
    }
    if (time->observed)
    {
        time->age_ms    = max(time->age_ms, userSaturatingSub(now, time->first_local_ms));
        time->age_valid = true;
    }
    if (time->age_valid)
        time->future_valid = false;
    time->age_sample_ms = now;
    return now;
}

static void userClientProjectExpiryLocked(User *user, uint64_t now)
{
    user_client_time_t *time     = &user->client_time;
    const uint64_t      duration = user->timeinfo.expire_after_first_usage_ms;
    uint64_t            relative = 0;
    bool                expired  = time->absolute_expired;
    if (duration != 0)
    {
        if (time->age_valid)
        {
            if (time->age_ms >= duration)
            {
                expired  = true;
                relative = max(now, UINT64_C(1));
            }
            else
                relative = userSaturatingAdd(now, duration - time->age_ms);
        }
        else if (time->future_valid)
            relative = userSaturatingAdd(time->future_origin_ms, duration);
    }
    const uint64_t absolute         = time->absolute_deadline_ms;
    user->client_view_expires_at_ms = absolute == 0 ? relative : relative == 0 ? absolute : min(absolute, relative);
    user->client_view_expired       = expired;
    user->client_view_expiry_valid  = true;
}

void userInstallClientClock(User *user, uint64_t server_time_ms, uint64_t accounting_time_ms, uint64_t received_at_ms)
{
    assert(userObjectIsInitialized(user) && accounting_time_ms != 0);
    rwlockWriteLock(&user->lock);
    user_client_time_t *time           = &user->client_time;
    const uint64_t      now            = userClientAdvanceAgeLocked(user, max(getHRTimeUs() / 1000ULL, received_at_ms));
    const uint64_t      elapsed        = userSaturatingSub(now, received_at_ms);
    const uint64_t      accounting_now = userSaturatingAdd(accounting_time_ms, elapsed);
    const uint64_t      first          = user->timeinfo.first_usage_at_ms;
    if (first != 0)
    {
        if (first <= accounting_now)
        {
            time->age_ms       = max(time->age_ms, accounting_now - first);
            time->age_valid    = true;
            time->future_valid = false;
        }
        else if (! time->age_valid)
        {
            const uint64_t origin = userSaturatingAdd(now, first - accounting_now);
            if (! time->future_valid || origin < time->future_origin_ms)
                time->future_origin_ms = origin;
            time->future_valid = true;
        }
    }
    const uint64_t config           = user->timeinfo.expire_at_ms;
    uint64_t       absolute         = 0;
    bool           absolute_expired = false;
    if (config != 0)
    {
        const uint64_t wall_now = userSaturatingAdd(server_time_ms, elapsed);
        absolute_expired        = config <= wall_now;
        absolute                = absolute_expired ? max(now, UINT64_C(1)) : userSaturatingAdd(now, config - wall_now);
        if (time->clock_valid && config == time->absolute_config_ms)
        {
            absolute = min(absolute, time->absolute_deadline_ms);
            absolute_expired |= time->absolute_expired;
        }
    }
    time->absolute_config_ms   = config;
    time->absolute_deadline_ms = absolute;
    time->absolute_expired     = absolute_expired;
    time->accounting_anchor_ms = accounting_time_ms;
    time->local_anchor_ms      = received_at_ms;
    time->clock_valid          = true;
    userClientProjectExpiryLocked(user, now);
    rwlockWriteUnlock(&user->lock);
}

void userGetAccountingSnapshot(User *user, user_accounting_snapshot_t *snapshot)
{
    assert(userObjectIsInitialized(user) && snapshot != NULL);
    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    *snapshot = (user_accounting_snapshot_t) {.id                = user->id,
                                              .traffic           = user->stats.traffic,
                                              .first_usage_at_ms = user->client_time.first_report_ms,
                                              .observation_pending =
                                                  user->client_time.observed && ! user->client_time.observation_acked};
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
}

void userAcknowledgeObservation(User *user, uint64_t first_usage_at_ms)
{
    assert(userObjectIsInitialized(user) && first_usage_at_ms != 0);
    rwlockWriteLock(&user->lock);
    if (user->client_time.observed && user->client_time.first_report_ms == first_usage_at_ms)
        user->client_time.observation_acked = true;
    rwlockWriteUnlock(&user->lock);
}

void userAddTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.traffic.u = userSaturatingAdd(user->stats.traffic.u, upload_bytes);
    user->stats.traffic.d = userSaturatingAdd(user->stats.traffic.d, download_bytes);
    rwlockWriteUnlock(&user->stats_lock);
}

void userAddSpeed(User *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.speed.u = upload_bytes_per_sec;
    user->stats.speed.d = download_bytes_per_sec;
    rwlockWriteUnlock(&user->stats_lock);
}

void userAddConnection(User *user, bool inbound)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    if (inbound)
    {
        user->stats.cons_in = userSaturatingAdd(user->stats.cons_in, 1);
    }
    else
    {
        user->stats.cons_out = userSaturatingAdd(user->stats.cons_out, 1);
    }
    rwlockWriteUnlock(&user->stats_lock);
}

void userRemoveConnection(User *user, bool inbound)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    if (inbound)
    {
        user->stats.cons_in = userSaturatingSub(user->stats.cons_in, 1);
    }
    else
    {
        user->stats.cons_out = userSaturatingSub(user->stats.cons_out, 1);
    }
    rwlockWriteUnlock(&user->stats_lock);
}

user_admission_result_t userTryAdmitConnection(User *user, const user_ip_key_t *ip_key, uint64_t now_ms)
{
    user_admission_result_t result = kUserAdmissionOk;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return kUserAdmissionInvalid;
    }

    /* Lock order matches userSnapshotCreate(): user->lock then user->stats_lock. */
    rwlockReadLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);

    result = userEligibilityLocked(user, now_ms);
    if (result != kUserAdmissionOk)
    {
        /* Eligibility refusal precedes any live reservation. */
    }
    else if (userLimitReached(user->limit.cons_out, user->runtime.active_cons_out))
    {
        result = kUserAdmissionConnectionLimited;
    }
    else
    {
        user_runtime_stat_t *runtime  = &user->runtime;
        bool                 track_ip = userIpKeyValid(ip_key);
        size_t               ip_index = runtime->ip_usage_count;

        if (track_ip)
        {
            ip_index = userRuntimeFindIpLocked(runtime, ip_key);

            // A previously unseen IP would push the distinct-IP set past the configured limit.
            if (ip_index == runtime->ip_usage_count && userLimitReached(user->limit.ips, runtime->ip_usage_count))
            {
                result = kUserAdmissionIpLimited;
            }
        }

        if (result == kUserAdmissionOk && track_ip)
        {
            if (ip_index < runtime->ip_usage_count)
            {
                runtime->ip_usages[ip_index].refs = userSaturatingAdd(runtime->ip_usages[ip_index].refs, 1);
            }
            else if (userRuntimeReserveIpLocked(runtime))
            {
                runtime->ip_usages[runtime->ip_usage_count].key  = *ip_key;
                runtime->ip_usages[runtime->ip_usage_count].refs = 1;
                runtime->ip_usage_count += 1;
                userRuntimeIpAddedLocked(runtime, runtime->ip_usage_count - 1U);
            }
            else
            {
                // Refuse rather than admit a connection we could not account for.
                result = kUserAdmissionInvalid;
            }
        }

        if (result == kUserAdmissionOk)
        {
            runtime->active_cons_out = userSaturatingAdd(runtime->active_cons_out, 1);
        }
    }

    rwlockWriteUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return result;
}

void userReleaseConnection(User *user, const user_ip_key_t *ip_key)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->runtime.active_cons_out = userSaturatingSub(user->runtime.active_cons_out, 1);

    if (userIpKeyValid(ip_key))
    {
        user_runtime_stat_t *runtime  = &user->runtime;
        size_t               ip_index = userRuntimeFindIpLocked(runtime, ip_key);
        if (ip_index < runtime->ip_usage_count)
        {
            if (runtime->ip_usages[ip_index].refs > 1)
            {
                runtime->ip_usages[ip_index].refs -= 1;
            }
            else
            {
                // Last connection from this IP: drop the slot (swap-with-last keeps the array dense).
                user_ip_key_t removed_key    = runtime->ip_usages[ip_index].key;
                size_t        old_last       = runtime->ip_usage_count - 1U;
                runtime->ip_usages[ip_index] = runtime->ip_usages[old_last];
                runtime->ip_usage_count -= 1;
                userRuntimeIpRemovedLocked(runtime, ip_index, &removed_key, old_last);
            }
        }
    }
    rwlockWriteUnlock(&user->stats_lock);
}

bool userAccountTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                        bool *first_usage_push_needed)
{
    return userAccountTrafficScaled(
        user, upload_bytes, download_bytes, kUserTrafficMultiplierScale, now_ms, first_usage_push_needed);
}

static uint64_t userScaleTrafficLocked(uint64_t bytes, uint32_t multiplier, uint32_t *remainder)
{
    assert(*remainder < kUserTrafficMultiplierScale);
    if (multiplier == kUserTrafficMultiplierScale)
    {
        return bytes;
    }

    /* Splitting before multiplication keeps both intermediates portable even
     * when raw bytes span all of uint64_t. The fractional product is < 10^9. */
    const uint64_t whole      = bytes / kUserTrafficMultiplierScale;
    const uint64_t fractional = (bytes % kUserTrafficMultiplierScale) * multiplier + *remainder;
    *remainder                = (uint32_t) (fractional % kUserTrafficMultiplierScale);
    if (whole > UINT64_MAX / multiplier)
    {
        return UINT64_MAX;
    }
    return userSaturatingAdd(whole * multiplier, fractional / kUserTrafficMultiplierScale);
}

/* User and stats write locks are held. Arrival observations and public
 * accounting share the same clock and coalesced first-use notification. */
static void userChargeTrafficLocked(User *user, uint64_t upload, uint64_t download, uint32_t multiplier)
{
    user->stats.traffic.u = userSaturatingAdd(
        user->stats.traffic.u, userScaleTrafficLocked(upload, multiplier, &user->runtime.traffic_remainder_u));
    user->stats.traffic.d = userSaturatingAdd(
        user->stats.traffic.d, userScaleTrafficLocked(download, multiplier, &user->runtime.traffic_remainder_d));
}

static uint64_t userObserveTrafficLocked(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                                         bool *first_usage_push_needed)
{
    if (user->client_time.clock_valid)
    {
        now_ms = userClientAdvanceAgeLocked(user, getHRTimeUs() / 1000ULL);
        if ((upload_bytes != 0 || download_bytes != 0) && ! user->client_time.observed)
        {
            user_client_time_t *time = &user->client_time;
            time->observed           = true;
            time->first_local_ms     = now_ms;
            time->first_report_ms =
                userSaturatingAdd(time->accounting_anchor_ms, userSaturatingSub(now_ms, time->local_anchor_ms));
            time->age_valid    = true;
            time->future_valid = false;
        }
        userClientProjectExpiryLocked(user, now_ms);
    }
    if (first_usage_push_needed != NULL && (upload_bytes != 0 || download_bytes != 0) &&
        (user->client_time.clock_valid ? ! user->client_time.observation_acked
                                       : user->timeinfo.first_usage_at_ms == 0) &&
        ! user->runtime.first_usage_push_requested)
    {
        user->runtime.first_usage_push_requested = true;
        *first_usage_push_needed                 = true;
    }
    return now_ms;
}

bool userObserveTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                        bool *first_usage_push_needed)
{
    assert(userObjectIsInitialized(user));
    if (first_usage_push_needed != NULL)
        *first_usage_push_needed = false;
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    now_ms     = userObserveTrafficLocked(user, upload_bytes, download_bytes, now_ms, first_usage_push_needed);
    bool close = userEligibilityLocked(user, now_ms) != kUserAdmissionOk;
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
    return close;
}

bool userAccountTrafficScaled(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint32_t multiplier,
                              uint64_t now_ms, bool *first_usage_push_needed)
{
    assert(multiplier > 0 && multiplier <= kUserTrafficMultiplierMax);
    bool should_close = false;

    if (first_usage_push_needed != NULL)
    {
        *first_usage_push_needed = false;
    }

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    now_ms = userObserveTrafficLocked(user, upload_bytes, download_bytes, now_ms, first_usage_push_needed);
    userChargeTrafficLocked(user, upload_bytes, download_bytes, multiplier);
    should_close = userEligibilityLocked(user, now_ms) != kUserAdmissionOk;
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
    return should_close;
}

bool userRuntimeShouldClose(User *user, uint64_t now_ms)
{
    bool should_close = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    should_close = userEligibilityLocked(user, now_ms) != kUserAdmissionOk;
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return should_close;
}

void userSetIpCount(User *user, uint64_t ips)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.ips = ips;
    rwlockWriteUnlock(&user->stats_lock);
}

void userSetDeviceCount(User *user, uint64_t devices)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.devices = devices;
    rwlockWriteUnlock(&user->stats_lock);
}

void userSetClientViewExpiry(User *user, uint64_t expires_at_ms, bool valid)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->client_view_expires_at_ms = valid ? expires_at_ms : 0;
    user->client_view_expiry_valid  = valid;
    user->client_view_expired       = false;
    rwlockWriteUnlock(&user->lock);
}

void userGetTimeInfo(User *user, user_time_info_t *timeinfo)
{
    if (UNLIKELY(! userObjectIsInitialized(user) || timeinfo == NULL))
    {
        return;
    }

    rwlockReadLock(&user->lock);
    *timeinfo = user->timeinfo;
    rwlockReadUnlock(&user->lock);
}

void userGetStats(User *user, user_stat_t *stats)
{
    if (UNLIKELY(! userObjectIsInitialized(user) || stats == NULL))
    {
        return;
    }

    rwlockReadLock(&user->stats_lock);
    *stats = user->stats;
    rwlockReadUnlock(&user->stats_lock);
}

user_stat_t userStatsDiff(User *base, User *current)
{
    user_stat_t base_stats    = {0};
    user_stat_t current_stats = {0};
    user_stat_t diff          = {0};

    if (UNLIKELY(! userObjectIsInitialized(base) || ! userObjectIsInitialized(current)))
    {
        return diff;
    }

    userGetStats(base, &base_stats);
    userGetStats(current, &current_stats);

    diff.ips       = userSaturatingSub(current_stats.ips, base_stats.ips);
    diff.devices   = userSaturatingSub(current_stats.devices, base_stats.devices);
    diff.cons_in   = userSaturatingSub(current_stats.cons_in, base_stats.cons_in);
    diff.cons_out  = userSaturatingSub(current_stats.cons_out, base_stats.cons_out);
    diff.speed.u   = userSaturatingSub(current_stats.speed.u, base_stats.speed.u);
    diff.speed.d   = userSaturatingSub(current_stats.speed.d, base_stats.speed.d);
    diff.traffic.u = userSaturatingSub(current_stats.traffic.u, base_stats.traffic.u);
    diff.traffic.d = userSaturatingSub(current_stats.traffic.d, base_stats.traffic.d);

    return diff;
}

static uint64_t userBandwidthCapacity(uint64_t rate)
{
    return max(UINT64_C(1), rate / 10U + (rate % 10U != 0));
}

void userBandwidthReconcileLocked(User *user, uint64_t now_ms)
{
    for (unsigned d = 0; d < 2; ++d)
    {
        user_bandwidth_state_t *state = &user->runtime.bandwidth[d];
        uint64_t                rate  = d == kUserBandwidthUpload ? user->limit.bandwidth.u : user->limit.bandwidth.d;
        if (! state->policy_valid && rate == 0)
            continue;
        if (state->policy_valid && state->rate == rate)
            continue;
        if (state->policy_valid && state->rate != 0)
        {
            uint64_t cap =
                state->oversized_ticket != 0 ? state->oversized_capacity : userBandwidthCapacity(state->rate);
            ratebucketRefill(&state->bucket, state->rate, cap, 1, now_ms);
            ratebucketClamp(&state->bucket, userBandwidthCapacity(state->rate));
        }
        if (! state->policy_valid || state->rate == 0)
        {
            ratebucketInit(&state->bucket, rate == 0 ? 0 : userBandwidthCapacity(rate));
            state->bucket.has_clock      = true;
            state->bucket.last_refill_ms = now_ms;
        }
        else if (rate != 0)
            ratebucketClamp(&state->bucket, userBandwidthCapacity(rate));
        state->rate               = rate;
        state->policy_valid       = true;
        state->oversized_ticket   = 0;
        state->oversized_capacity = 0;
    }
}

static user_bandwidth_waiter_t *userBandwidthFind(user_bandwidth_state_t *state, uint64_t ticket)
{
    for (user_bandwidth_waiter_t *w = state->head; w != NULL; w = w->next)
        if (w->ticket == ticket)
            return w;
    return NULL;
}

static user_bandwidth_waiter_t *userBandwidthHead(user_bandwidth_state_t *state)
{
    for (user_bandwidth_waiter_t *w = state->head; w != NULL; w = w->next)
        if (w->eligible)
            return w;
    return NULL;
}

static void userBandwidthUnlink(user_bandwidth_state_t *state, user_bandwidth_waiter_t *waiter)
{
    user_bandwidth_waiter_t **link = &state->head;
    user_bandwidth_waiter_t  *prev = NULL;
    while (*link != waiter)
    {
        assert(*link != NULL);
        prev = *link;
        link = &(*link)->next;
    }
    *link = waiter->next;
    if (state->tail == waiter)
        state->tail = prev;
    waiter->next = NULL;
}

static void userBandwidthAppend(user_bandwidth_state_t *state, user_bandwidth_waiter_t *waiter)
{
    if (state->tail != NULL)
        state->tail->next = waiter;
    else
        state->head = waiter;
    state->tail = waiter;
}

static void userBandwidthEndOversized(user_bandwidth_state_t *state, uint64_t ticket, uint64_t now)
{
    if (state->oversized_ticket != ticket || ticket == 0)
        return;
    ratebucketRefill(&state->bucket, state->rate, state->oversized_capacity, 1, now);
    ratebucketClamp(&state->bucket, userBandwidthCapacity(state->rate));
    state->oversized_ticket = state->oversized_capacity = 0;
}

bool userBandwidthRegister(User *user, user_bandwidth_direction_t direction, uint64_t ticket)
{
    assert(userObjectIsInitialized(user) && direction <= kUserBandwidthDownload && ticket != 0);
    rwlockReadLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    bool ok = user->runtime.bandwidth_waiter_count < 1024;
    if (ok)
    {
        user_bandwidth_state_t *state = &user->runtime.bandwidth[direction];
        assert(userBandwidthFind(state, ticket) == NULL);
        user_bandwidth_waiter_t *waiter = memoryAllocateZero(sizeof(*waiter));
        waiter->ticket                  = ticket;
        userBandwidthAppend(state, waiter);
        ++user->runtime.bandwidth_waiter_count;
    }
    rwlockWriteUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return ok;
}

void userBandwidthSetEligible(User *user, user_bandwidth_direction_t direction, uint64_t ticket, bool eligible)
{
    assert(direction <= kUserBandwidthDownload && ticket != 0);
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    user_bandwidth_state_t  *state  = &user->runtime.bandwidth[direction];
    user_bandwidth_waiter_t *waiter = userBandwidthFind(state, ticket);
    if (waiter != NULL && waiter->eligible != eligible)
    {
        uint64_t now = getHRTimeUs() / 1000U;
        userBandwidthReconcileLocked(user, now);
        userBandwidthEndOversized(state, ticket, now);
        waiter->eligible = eligible;
        if (eligible)
        {
            userBandwidthUnlink(state, waiter);
            userBandwidthAppend(state, waiter);
        }
    }
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
}

static bool userBandwidthCostFits(buffer_budget_cost_t used, buffer_budget_cost_t cost, buffer_budget_cost_t limit)
{
    return cost.bytes <= limit.bytes - used.bytes && cost.charge <= limit.charge - used.charge &&
           cost.entries <= limit.entries - used.entries;
}

static void userBandwidthAddCost(buffer_budget_cost_t *used, buffer_budget_cost_t cost)
{
    used->bytes += cost.bytes;
    used->charge += cost.charge;
    used->entries += cost.entries;
}

static void userBandwidthSubtractCost(buffer_budget_cost_t *used, buffer_budget_cost_t cost)
{
    assert(cost.bytes <= used->bytes && cost.charge <= used->charge && cost.entries <= used->entries);
    used->bytes -= cost.bytes;
    used->charge -= cost.charge;
    used->entries -= cost.entries;
}

bool userBandwidthReserve(User *user, user_bandwidth_direction_t direction, uint64_t ticket, buffer_budget_cost_t cost)
{
    assert(direction <= kUserBandwidthDownload && ticket != 0);
    rwlockWriteLock(&user->stats_lock);
    user_bandwidth_waiter_t *waiter = userBandwidthFind(&user->runtime.bandwidth[direction], ticket);
    bool                     ok     = waiter != NULL &&
              userBandwidthCostFits(user->runtime.queued_cost, cost, (buffer_budget_cost_t) {4U << 20, 8U << 20, 1024});
    if (ok)
    {
        userBandwidthAddCost(&user->runtime.queued_cost, cost);
        userBandwidthAddCost(&waiter->cost, cost);
    }
    rwlockWriteUnlock(&user->stats_lock);
    return ok;
}

void userBandwidthRelease(User *user, user_bandwidth_direction_t direction, uint64_t ticket, buffer_budget_cost_t cost)
{
    assert(direction <= kUserBandwidthDownload && ticket != 0);
    rwlockWriteLock(&user->stats_lock);
    user_bandwidth_waiter_t *waiter = userBandwidthFind(&user->runtime.bandwidth[direction], ticket);
    if (waiter != NULL)
    {
        userBandwidthSubtractCost(&waiter->cost, cost);
        userBandwidthSubtractCost(&user->runtime.queued_cost, cost);
    }
    rwlockWriteUnlock(&user->stats_lock);
}

void userBandwidthCancel(User *user, user_bandwidth_direction_t direction, uint64_t ticket)
{
    assert(direction <= kUserBandwidthDownload && ticket != 0);
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    user_bandwidth_state_t  *state  = &user->runtime.bandwidth[direction];
    user_bandwidth_waiter_t *waiter = userBandwidthFind(state, ticket);
    if (waiter != NULL)
    {
        uint64_t now = getHRTimeUs() / 1000U;
        userBandwidthReconcileLocked(user, now);
        userBandwidthEndOversized(state, ticket, now);
        userBandwidthUnlink(state, waiter);
        userBandwidthSubtractCost(&user->runtime.queued_cost, waiter->cost);
        --user->runtime.bandwidth_waiter_count;
        memoryFree(waiter);
    }
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
}

/* Both locks are held, and now is a fresh process-wide clock sample. Preview
 * never spends credit; activation of an oversized head settles ordinary credit
 * before the larger cap is installed. */
static user_bandwidth_result_t userBandwidthPreviewLocked(User *user, user_bandwidth_direction_t direction,
                                                          uint64_t ticket, uint64_t bytes, bool datagram, uint64_t now,
                                                          uint64_t expiry_now)
{
    user_bandwidth_result_t result = {.decision = kUserDeliveryReject};
    if (userEligibilityLocked(user, expiry_now) != kUserAdmissionOk || (datagram && bytes > 65535))
        return result;
    userBandwidthReconcileLocked(user, now);
    user_bandwidth_state_t  *state  = &user->runtime.bandwidth[direction];
    user_bandwidth_waiter_t *head   = userBandwidthHead(state);
    user_bandwidth_waiter_t *waiter = ticket == 0 ? NULL : userBandwidthFind(state, ticket);
    if (ticket != 0 && waiter == NULL)
        return result;
    if ((ticket != 0 && ! waiter->eligible) || (head != NULL && head->ticket != ticket))
        return (user_bandwidth_result_t) {.decision = kUserDeliveryWait, .retry_ms = 10};
    uint64_t wanted = datagram || (ticket == 0 && state->rate == 0) ? bytes : min(bytes, UINT64_C(16384));
    if (state->rate == 0)
        return (user_bandwidth_result_t) {.decision = kUserDeliveryForward, .grant = wanted};
    uint64_t ordinary = userBandwidthCapacity(state->rate);
    uint64_t cap      = state->oversized_ticket != 0 ? state->oversized_capacity : ordinary;
    ratebucketRefill(&state->bucket, state->rate, cap, 1, now);
    if (datagram && bytes > ordinary && ticket != 0 && state->oversized_ticket == 0)
    {
        state->oversized_ticket   = ticket;
        state->oversized_capacity = bytes;
    }
    uint64_t available = ratebucketAvailable(&state->bucket);
    uint64_t grant     = datagram ? (available >= wanted ? wanted : 0) : min(wanted, available);
    if (grant != 0 || bytes == 0)
        return (user_bandwidth_result_t) {.decision = kUserDeliveryForward, .grant = grant};
    uint64_t retry = ratebucketRetryMs(&state->bucket, state->rate, 1, now, datagram ? wanted : 1);
    return (user_bandwidth_result_t) {.decision = kUserDeliveryWait,
                                      .retry_ms = min(max(retry, UINT64_C(1)), UINT64_C(100))};
}

user_bandwidth_result_t userBandwidthPreview(User *user, user_bandwidth_direction_t direction, uint64_t ticket,
                                             uint64_t bytes, bool datagram)
{
    assert(userObjectIsInitialized(user) && direction <= kUserBandwidthDownload);
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    uint64_t now = getHRTimeUs() / 1000U;
    if (user->client_time.clock_valid)
    {
        now = userClientAdvanceAgeLocked(user, now);
        userClientProjectExpiryLocked(user, now);
    }
    user_bandwidth_result_t result = userBandwidthPreviewLocked(
        user, direction, ticket, bytes, datagram, now, user->client_view_expiry_valid ? now : getTimeOfDayMS());
    result.limited = (direction == kUserBandwidthUpload ? user->limit.bandwidth.u : user->limit.bandwidth.d) != 0;
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
    return result;
}

user_delivery_decision_t userCommitDelivery(User *user, user_bandwidth_direction_t direction, uint64_t ticket,
                                            uint64_t bytes, bool datagram, bool more, uint32_t multiplier)
{
    assert(userObjectIsInitialized(user) && direction <= kUserBandwidthDownload && multiplier != 0 &&
           multiplier <= kUserTrafficMultiplierMax);
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    uint64_t now = getHRTimeUs() / 1000U;
    if (user->client_time.clock_valid)
    {
        now = userClientAdvanceAgeLocked(user, now);
        userClientProjectExpiryLocked(user, now);
    }
    user_bandwidth_result_t preview = userBandwidthPreviewLocked(
        user, direction, ticket, bytes, datagram, now, user->client_view_expiry_valid ? now : getTimeOfDayMS());
    user_delivery_decision_t result = preview.decision;
    if (result == kUserDeliveryForward && preview.grant < bytes)
        result = kUserDeliveryWait;
    if (result == kUserDeliveryForward)
    {
        user_bandwidth_state_t *state = &user->runtime.bandwidth[direction];
        if (state->rate != 0)
        {
            uint64_t granted = ratebucketGrant(&state->bucket, bytes, false);
            assert(granted == bytes);
            discard granted;
        }
        userBandwidthEndOversized(state, ticket, now);
        userChargeTrafficLocked(user,
                                direction == kUserBandwidthUpload ? bytes : 0,
                                direction == kUserBandwidthDownload ? bytes : 0,
                                multiplier);
        if (ticket != 0)
        {
            user_bandwidth_waiter_t *waiter = userBandwidthFind(state, ticket);
            assert(waiter != NULL);
            waiter->eligible = more;
            userBandwidthUnlink(state, waiter);
            userBandwidthAppend(state, waiter);
        }
        if (userTrafficReachedLocked(user))
            result = kUserDeliveryForwardClose;
    }
    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
    return result;
}
