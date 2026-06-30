#include "structure.h"

#include "loggers/network_logger.h"

void softiplimiterTunnelstateInitialize(softiplimiter_tstate_t *ts)
{
    rwlockinit(&ts->table_lock);
    ts->table                   = softiplimiter_identity_map_t_with_capacity(kSoftIpLimiterInitialTableCap);
    ts->identifier_mode         = kSoftIpLimiterIdentifierNone;
    ts->tolerance_ms            = 0;
    ts->simultaneous_user_limit = 0;
    ts->verbose                 = false;
}

void softiplimiterTunnelstateDestroy(softiplimiter_tstate_t *ts)
{
    softiplimiter_identity_map_t_drop(&ts->table);
    rwlockDestroy(&ts->table_lock);
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

uint64_t softiplimiterNowMs(void)
{
    // Cached, syscall-free clock for the current worker loop. Granularity is one
    // loop iteration, which is well within the ms-scale tolerance this node uses.
    return getWorkerNowMS(getWID());
}

const char *softiplimiterIdentifierModeName(softiplimiter_identifier_mode_t mode)
{
    switch (mode)
    {
    case kSoftIpLimiterIdentifierVless:
        return "vless";
    case kSoftIpLimiterIdentifierTrojan:
        return "trojan";
    case kSoftIpLimiterIdentifierNone:
    default:
        return "unknown";
    }
}

static const char *softiplimiterTableReasonName(softiplimiter_table_reason_t reason)
{
    switch (reason)
    {
    case kSoftIpLimiterTableOk:
        return "ok";
    case kSoftIpLimiterTableLimitReached:
        return "ip limit reached";
    case kSoftIpLimiterTableMissingRow:
        return "ip row missing or expired";
    case kSoftIpLimiterTableMissingIp:
        return "missing source IP";
    default:
        return "unknown";
    }
}

bool softiplimiterIpKeyEqual(const softiplimiter_ip_key_t *a, const softiplimiter_ip_key_t *b)
{
    return a->type == b->type && memoryCompare(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

bool softiplimiterBuildIpKey(line_t *l, softiplimiter_ip_key_t *out)
{
    memoryZero(out, sizeof(*out));

    const address_context_t *src = lineGetSourceAddressContext(l);
    if (! addresscontextIsIp(src))
    {
        return false;
    }

    const ip_addr_t *ip = &src->ip_address;
    if (ip->type == IPADDR_TYPE_V4)
    {
        out->type = 4;
        memoryCopy(out->bytes, &ip->u_addr.ip4.addr, sizeof(ip->u_addr.ip4.addr));
        return true;
    }

    if (ip->type == IPADDR_TYPE_V6)
    {
        out->type = 6;
        memoryCopy(out->bytes, ip->u_addr.ip6.addr, sizeof(ip->u_addr.ip6.addr));
        return true;
    }

    return false;
}

void softiplimiterFormatIpKey(const softiplimiter_ip_key_t *ip_key, char *out, size_t out_len)
{
    if (out_len == 0)
    {
        return;
    }

    if (ip_key == NULL)
    {
        snprintf(out, out_len, "<none>");
        return;
    }

    if (ip_key->type == 4)
    {
        snprintf(out,
                 out_len,
                 "%u.%u.%u.%u",
                 (unsigned int) ip_key->bytes[0],
                 (unsigned int) ip_key->bytes[1],
                 (unsigned int) ip_key->bytes[2],
                 (unsigned int) ip_key->bytes[3]);
        return;
    }

    if (ip_key->type == 6)
    {
        snprintf(out,
                 out_len,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (unsigned int) ip_key->bytes[0],
                 (unsigned int) ip_key->bytes[1],
                 (unsigned int) ip_key->bytes[2],
                 (unsigned int) ip_key->bytes[3],
                 (unsigned int) ip_key->bytes[4],
                 (unsigned int) ip_key->bytes[5],
                 (unsigned int) ip_key->bytes[6],
                 (unsigned int) ip_key->bytes[7],
                 (unsigned int) ip_key->bytes[8],
                 (unsigned int) ip_key->bytes[9],
                 (unsigned int) ip_key->bytes[10],
                 (unsigned int) ip_key->bytes[11],
                 (unsigned int) ip_key->bytes[12],
                 (unsigned int) ip_key->bytes[13],
                 (unsigned int) ip_key->bytes[14],
                 (unsigned int) ip_key->bytes[15]);
        return;
    }

    snprintf(out, out_len, "<invalid:%u>", (unsigned int) ip_key->type);
}

static bool softiplimiterTrojanPrefixCanBeTrojanBytes(const uint8_t *bytes, size_t len)
{
    size_t inspect = min(len, (size_t) kSoftIpLimiterTrojanPasswordLen);
    for (size_t i = 0; i < inspect; ++i)
    {
        if (UNLIKELY(asciiHexValue(bytes[i]) < 0))
        {
            return false;
        }
    }

    if (UNLIKELY(len > kSoftIpLimiterTrojanPasswordLen && bytes[kSoftIpLimiterTrojanPasswordLen] != '\r'))
    {
        return false;
    }

    if (UNLIKELY(len > kSoftIpLimiterTrojanPasswordLen + 1U &&
                 bytes[kSoftIpLimiterTrojanPasswordLen + 1U] != '\n'))
    {
        return false;
    }

    return true;
}

softiplimiter_extract_result_t softiplimiterTryExtractIdentifierFromBytes(softiplimiter_identifier_mode_t mode,
                                                                          const uint8_t *bytes,
                                                                          size_t len,
                                                                          hash_t *identifier_out)
{
    if (UNLIKELY(identifier_out == NULL))
    {
        return kSoftIpLimiterExtractInvalid;
    }

    if (mode == kSoftIpLimiterIdentifierVless)
    {
        if (len < 1)
        {
            return kSoftIpLimiterExtractWait;
        }
        if (UNLIKELY(bytes[0] != kSoftIpLimiterVlessVersion))
        {
            return kSoftIpLimiterExtractInvalid;
        }
        if (len < 1U + kSoftIpLimiterVlessUuidLen)
        {
            return kSoftIpLimiterExtractWait;
        }

        *identifier_out = calcHashBytes(bytes + 1, kSoftIpLimiterVlessUuidLen);
        return kSoftIpLimiterExtractOk;
    }

    if (mode == kSoftIpLimiterIdentifierTrojan)
    {
        if (UNLIKELY(! softiplimiterTrojanPrefixCanBeTrojanBytes(bytes, len)))
        {
            return kSoftIpLimiterExtractInvalid;
        }
        if (len < kSoftIpLimiterTrojanPasswordLen)
        {
            return kSoftIpLimiterExtractWait;
        }

        uint8_t sha224[SHA224_DIGEST_SIZE] = {0};
        if (UNLIKELY(! asciiHexDecodeBytes(bytes, kSoftIpLimiterTrojanPasswordLen, sha224, sizeof(sha224))))
        {
            memoryZero(sha224, sizeof(sha224));
            return kSoftIpLimiterExtractInvalid;
        }

        *identifier_out = calcHashBytes(sha224, sizeof(sha224));
        memoryZero(sha224, sizeof(sha224));
        return kSoftIpLimiterExtractOk;
    }

    return kSoftIpLimiterExtractInvalid;
}

softiplimiter_extract_result_t softiplimiterTryExtractIdentifierFromStream(softiplimiter_identifier_mode_t mode,
                                                                           buffer_stream_t *stream,
                                                                           hash_t *identifier_out)
{
    size_t available = bufferstreamGetBufLen(stream);

    if (mode == kSoftIpLimiterIdentifierVless)
    {
        if (available < 1)
        {
            return kSoftIpLimiterExtractWait;
        }
        if (UNLIKELY(bufferstreamViewByteAt(stream, 0) != kSoftIpLimiterVlessVersion))
        {
            return kSoftIpLimiterExtractInvalid;
        }
        if (available < 1U + kSoftIpLimiterVlessUuidLen)
        {
            return kSoftIpLimiterExtractWait;
        }

        uint8_t uuid[kSoftIpLimiterVlessUuidLen] = {0};
        bufferstreamViewBytesAt(stream, 1, uuid, sizeof(uuid));
        *identifier_out = calcHashBytes(uuid, sizeof(uuid));
        memoryZero(uuid, sizeof(uuid));
        return kSoftIpLimiterExtractOk;
    }

    if (mode == kSoftIpLimiterIdentifierTrojan)
    {
        size_t  inspect_len = min(available, (size_t) kSoftIpLimiterTrojanPasswordLen + 2U);
        uint8_t inspect[kSoftIpLimiterTrojanPasswordLen + 2U] = {0};
        if (inspect_len > 0)
        {
            bufferstreamViewBytesAt(stream, 0, inspect, inspect_len);
        }
        return softiplimiterTryExtractIdentifierFromBytes(mode, inspect, inspect_len, identifier_out);
    }

    return kSoftIpLimiterExtractInvalid;
}

static bool softiplimiterRowExpired(const softiplimiter_ip_row_t *row, uint64_t tolerance_ms, uint64_t now_ms)
{
    uint64_t last_seen = atomicLoadRelaxed(&row->last_seen_ms);
    return now_ms > last_seen && now_ms - last_seen > tolerance_ms;
}

static void softiplimiterEntryRemoveAt(softiplimiter_identity_entry_t *entry, uint8_t index)
{
    assert(index < entry->ip_count);

    entry->ip_count -= 1U;
    if (index != entry->ip_count)
    {
        entry->ips[index] = entry->ips[entry->ip_count];
    }
    memoryZero(&entry->ips[entry->ip_count], sizeof(entry->ips[entry->ip_count]));
}

static void softiplimiterPruneEntry(softiplimiter_identity_entry_t *entry, uint64_t tolerance_ms, uint64_t now_ms)
{
    uint8_t i = 0;
    while (i < entry->ip_count)
    {
        if (softiplimiterRowExpired(&entry->ips[i], tolerance_ms, now_ms))
        {
            softiplimiterEntryRemoveAt(entry, i);
            continue;
        }
        i += 1U;
    }
}

static int softiplimiterFindIpRow(const softiplimiter_identity_entry_t *entry, const softiplimiter_ip_key_t *ip_key)
{
    for (uint8_t i = 0; i < entry->ip_count; ++i)
    {
        if (softiplimiterIpKeyEqual(&entry->ips[i].ip_key, ip_key))
        {
            return (int) i;
        }
    }

    return -1;
}

static void softiplimiterTableResultSet(softiplimiter_table_result_t *result, softiplimiter_table_reason_t reason,
                                        uint8_t count, uint8_t limit)
{
    if (result == NULL)
    {
        return;
    }

    *result = (softiplimiter_table_result_t) {
        .reason = reason,
        .count  = count,
        .limit  = limit,
    };
}

bool softiplimiterTableAdmit(softiplimiter_identity_map_t *table, hash_t identifier,
                             const softiplimiter_ip_key_t *ip_key, uint8_t limit, uint64_t tolerance_ms,
                             uint64_t now_ms, softiplimiter_table_result_t *result)
{
    softiplimiter_identity_map_t_iter it = softiplimiter_identity_map_t_find(table, identifier);
    softiplimiter_identity_entry_t   *entry = NULL;

    if (it.ref == softiplimiter_identity_map_t_end(table).ref)
    {
        softiplimiter_identity_entry_t new_entry = {0};
        softiplimiter_identity_map_t_result insert_result =
            softiplimiter_identity_map_t_insert(table, identifier, new_entry);
        entry = &insert_result.ref->second;
    }
    else
    {
        entry = &it.ref->second;
    }

    softiplimiterPruneEntry(entry, tolerance_ms, now_ms);

    int row_index = softiplimiterFindIpRow(entry, ip_key);
    if (row_index >= 0)
    {
        softiplimiter_ip_row_t *row = &entry->ips[row_index];
        row->refs += 1U;
        atomicStoreRelaxed(&row->last_seen_ms, now_ms);
        softiplimiterTableResultSet(result, kSoftIpLimiterTableOk, entry->ip_count, limit);
        return true;
    }

    if (entry->ip_count >= limit)
    {
        softiplimiterTableResultSet(result, kSoftIpLimiterTableLimitReached, entry->ip_count, limit);
        return false;
    }

    softiplimiter_ip_row_t *row = &entry->ips[entry->ip_count];
    row->ip_key = *ip_key;
    row->refs   = 1;
    atomicStoreRelaxed(&row->last_seen_ms, now_ms);
    entry->ip_count += 1U;
    softiplimiterTableResultSet(result, kSoftIpLimiterTableOk, entry->ip_count, limit);
    return true;
}

bool softiplimiterTableTouch(softiplimiter_identity_map_t *table, hash_t identifier,
                             const softiplimiter_ip_key_t *ip_key, uint8_t limit, uint64_t tolerance_ms,
                             uint64_t now_ms, softiplimiter_table_result_t *result)
{
    softiplimiter_identity_map_t_iter it = softiplimiter_identity_map_t_find(table, identifier);
    if (it.ref == softiplimiter_identity_map_t_end(table).ref)
    {
        softiplimiterTableResultSet(result, kSoftIpLimiterTableMissingRow, 0, limit);
        return false;
    }

    softiplimiter_identity_entry_t *entry = &it.ref->second;
    softiplimiterPruneEntry(entry, tolerance_ms, now_ms);

    int row_index = softiplimiterFindIpRow(entry, ip_key);
    if (row_index < 0)
    {
        uint8_t count = entry->ip_count;
        if (entry->ip_count == 0)
        {
            softiplimiter_identity_map_t_erase_at(table, it);
        }
        softiplimiterTableResultSet(result, kSoftIpLimiterTableMissingRow, count, limit);
        return false;
    }

    atomicStoreRelaxed(&entry->ips[row_index].last_seen_ms, now_ms);
    softiplimiterTableResultSet(result, kSoftIpLimiterTableOk, entry->ip_count, limit);
    return true;
}

// Fast path for the steady-state touch: refresh last_seen for an existing,
// non-expired row while holding only a shared (read) lock. Performs no structural
// mutation, so many workers can refresh concurrently. Returns false when the row
// is absent or expired, signalling the caller to retry under the exclusive lock
// where pruning, erase and rejection accounting happen.
static bool softiplimiterTableTouchShared(softiplimiter_identity_map_t *table, hash_t identifier,
                                          const softiplimiter_ip_key_t *ip_key, uint64_t tolerance_ms,
                                          uint64_t now_ms)
{
    softiplimiter_identity_map_t_iter it = softiplimiter_identity_map_t_find(table, identifier);
    if (it.ref == softiplimiter_identity_map_t_end(table).ref)
    {
        return false;
    }

    softiplimiter_identity_entry_t *entry = &it.ref->second;
    for (uint8_t i = 0; i < entry->ip_count; ++i)
    {
        if (softiplimiterIpKeyEqual(&entry->ips[i].ip_key, ip_key))
        {
            if (softiplimiterRowExpired(&entry->ips[i], tolerance_ms, now_ms))
            {
                return false; // expired: exclusive path prunes the row and closes the line
            }
            atomicStoreRelaxed(&entry->ips[i].last_seen_ms, now_ms);
            return true;
        }
    }

    return false; // row not present: exclusive path decides (may erase empty entry)
}

void softiplimiterTableRelease(softiplimiter_identity_map_t *table, hash_t identifier,
                               const softiplimiter_ip_key_t *ip_key, uint64_t tolerance_ms, uint64_t now_ms)
{
    softiplimiter_identity_map_t_iter it = softiplimiter_identity_map_t_find(table, identifier);
    if (it.ref == softiplimiter_identity_map_t_end(table).ref)
    {
        return;
    }

    softiplimiter_identity_entry_t *entry = &it.ref->second;
    softiplimiterPruneEntry(entry, tolerance_ms, now_ms);

    int row_index = softiplimiterFindIpRow(entry, ip_key);
    if (row_index >= 0)
    {
        softiplimiter_ip_row_t *row = &entry->ips[row_index];
        if (row->refs > 1U)
        {
            row->refs -= 1U;
        }
        else
        {
            softiplimiterEntryRemoveAt(entry, (uint8_t) row_index);
        }
    }

    if (entry->ip_count == 0)
    {
        softiplimiter_identity_map_t_erase_at(table, it);
    }
}

bool softiplimiterAdmitLine(tunnel_t *t, line_t *l, softiplimiter_lstate_t *ls, uint64_t now_ms,
                            softiplimiter_table_result_t *result)
{
    softiplimiter_tstate_t *ts = tunnelGetState(t);

    if (! softiplimiterBuildIpKey(l, &ls->ip_key))
    {
        ls->ip_key_valid = false;
        softiplimiterTableResultSet(result, kSoftIpLimiterTableMissingIp, 0, ts->simultaneous_user_limit);
        return false;
    }
    ls->ip_key_valid = true;

    rwlockWriteLock(&ts->table_lock);
    bool ok = softiplimiterTableAdmit(&ts->table,
                                      ls->identifier,
                                      &ls->ip_key,
                                      ts->simultaneous_user_limit,
                                      ts->tolerance_ms,
                                      now_ms,
                                      result);
    rwlockWriteUnlock(&ts->table_lock);

    if (ok)
    {
        ls->admitted = true;
    }
    return ok;
}

bool softiplimiterTouchLine(tunnel_t *t, softiplimiter_lstate_t *ls, uint64_t now_ms,
                            softiplimiter_table_result_t *result)
{
    softiplimiter_tstate_t *ts = tunnelGetState(t);

    if (! ls->admitted || ! ls->ip_key_valid)
    {
        softiplimiterTableResultSet(result, kSoftIpLimiterTableMissingRow, 0, ts->simultaneous_user_limit);
        return false;
    }

    // Fast path: shared read lock + atomic refresh for the common active case, so
    // concurrent workers do not serialize on the table lock for every payload.
    rwlockReadLock(&ts->table_lock);
    bool refreshed =
        softiplimiterTableTouchShared(&ts->table, ls->identifier, &ls->ip_key, ts->tolerance_ms, now_ms);
    rwlockReadUnlock(&ts->table_lock);
    if (LIKELY(refreshed))
    {
        softiplimiterTableResultSet(result, kSoftIpLimiterTableOk, 0, ts->simultaneous_user_limit);
        return true;
    }

    // Slow path: exclusive lock for pruning, erase and accurate rejection result.
    // Only reached when the row is missing or has expired (i.e. about to close).
    rwlockWriteLock(&ts->table_lock);
    bool ok = softiplimiterTableTouch(&ts->table,
                                      ls->identifier,
                                      &ls->ip_key,
                                      ts->simultaneous_user_limit,
                                      ts->tolerance_ms,
                                      now_ms,
                                      result);
    rwlockWriteUnlock(&ts->table_lock);

    return ok;
}

void softiplimiterReleaseLine(tunnel_t *t, softiplimiter_lstate_t *ls)
{
    if (! ls->admitted || ! ls->ip_key_valid)
    {
        return;
    }

    softiplimiter_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->table_lock);
    softiplimiterTableRelease(&ts->table, ls->identifier, &ls->ip_key, ts->tolerance_ms, softiplimiterNowMs());
    rwlockWriteUnlock(&ts->table_lock);

    ls->admitted = false;
}

static void softiplimiterLogLine(tunnel_t *t, line_t *l, const softiplimiter_lstate_t *ls, const char *action,
                                 const char *reason, const softiplimiter_table_result_t *result)
{
    softiplimiter_tstate_t *ts = tunnelGetState(t);
    if (! ts->verbose)
    {
        return;
    }

    char ip[80] = {0};
    if (ls != NULL && ls->ip_key_valid)
    {
        softiplimiterFormatIpKey(&ls->ip_key, ip, sizeof(ip));
    }
    else
    {
        snprintf(ip, sizeof(ip), "<none>");
    }

    uint8_t count = result != NULL ? result->count : 0;
    uint8_t limit = result != NULL ? result->limit : ts->simultaneous_user_limit;
    const char *detail = reason != NULL ? reason
                                        : softiplimiterTableReasonName(result != NULL ? result->reason
                                                                                      : kSoftIpLimiterTableOk);

    LOGW("SoftIpLimiter: %s on worker %u: mode=%s identifier=%" PRIu64
         " source-ip=%s reason=\"%s\" ip-count=%u limit=%u",
         action,
         l != NULL ? (unsigned int) lineGetWID(l) : (unsigned int) getWID(),
         softiplimiterIdentifierModeName(ts->identifier_mode),
         ls != NULL ? (uint64_t) ls->identifier : 0,
         ip,
         detail,
         (unsigned int) count,
         (unsigned int) limit);
}

void softiplimiterLogRejected(tunnel_t *t, line_t *l, const softiplimiter_lstate_t *ls, const char *reason,
                              const softiplimiter_table_result_t *result)
{
    softiplimiterLogLine(t, l, ls, "rejected connection", reason, result);
}

void softiplimiterLogActiveClose(tunnel_t *t, line_t *l, const softiplimiter_lstate_t *ls, const char *reason,
                                 const softiplimiter_table_result_t *result)
{
    softiplimiterLogLine(t, l, ls, "closing active connection", reason, result);
}

void softiplimiterCloseLine(tunnel_t *t, line_t *l, softiplimiter_close_origin_t origin)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);

    if (ls->closing)
    {
        return;
    }

    bool close_next = origin != kSoftIpLimiterCloseFromNext && ls->next_init_sent;
    bool close_prev = origin != kSoftIpLimiterCloseFromPrev;

    ls->closing = true;
    ls->phase   = kSoftIpLimiterPhaseClosing;
    lineLock(l);

    softiplimiterReleaseLine(t, ls);
    /* Finish must not reflect to the initiating side; close targets are captured before destroying this state. */
    softiplimiterLinestateDestroy(ls);

    if (close_next && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (close_prev && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

static bool softiplimiterEnsureNextInitAndFlush(tunnel_t *t, line_t *l, softiplimiter_lstate_t *ls)
{
    if (! ls->next_init_sent)
    {
        ls->next_init_sent = true;
        if (! withLineLocked(l, tunnelNextUpStreamInit, t))
        {
            return false;
        }
    }

    ls = lineGetState(l, t);
    if (UNLIKELY(! ls->next_init_sent || ls->closing || ls->phase == kSoftIpLimiterPhaseClosing))
    {
        return false;
    }
    ls->phase = kSoftIpLimiterPhaseEstablished;

    sbuf_t *replay = bufferstreamFullRead(&ls->in_stream);
    if (replay != NULL && ! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, replay))
    {
        return false;
    }

    return true;
}

void softiplimiterHandleInitialPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    softiplimiter_tstate_t *ts = tunnelGetState(t);
    softiplimiter_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&ls->in_stream, buf);

    hash_t identifier = 0;
    softiplimiter_extract_result_t extract =
        softiplimiterTryExtractIdentifierFromStream(ts->identifier_mode, &ls->in_stream, &identifier);

    if (extract == kSoftIpLimiterExtractWait)
    {
        return;
    }

    if (UNLIKELY(extract != kSoftIpLimiterExtractOk))
    {
        ls->ip_key_valid = softiplimiterBuildIpKey(l, &ls->ip_key);
        softiplimiterLogRejected(t, l, ls, "malformed or unsupported early identity", NULL);
        softiplimiterCloseLine(t, l, kSoftIpLimiterCloseInternal);
        return;
    }

    ls->identifier = identifier;

    softiplimiter_table_result_t result = {0};
    if (UNLIKELY(! softiplimiterAdmitLine(t, l, ls, softiplimiterNowMs(), &result)))
    {
        softiplimiterLogRejected(t, l, ls, softiplimiterTableReasonName(result.reason), &result);
        softiplimiterCloseLine(t, l, kSoftIpLimiterCloseInternal);
        return;
    }

    discard softiplimiterEnsureNextInitAndFlush(t, l, ls);
}
