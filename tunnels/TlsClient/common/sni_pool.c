#include "sni_pool.h"

#include "loggers/network_logger.h"

#include <limits.h>

static void tlsclientDestroyAfterSniConfigError(tlsclient_tstate_t *ts, tunnel_t *t)
{
    tlsclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}

static bool tlsclientLoadSniString(char **dest, const cJSON *item, const char *json_path)
{
    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("JSON Error: %s (string field) : The data was empty or invalid", json_path);
        return false;
    }

    *dest = stringDuplicate(item->valuestring);
    return true;
}

static bool tlsclientAllocateSniStats(tlsclient_tstate_t *ts)
{
    if (ts->sni_stats != NULL)
    {
        return true;
    }

    if (ts->snis_count == 0)
    {
        return false;
    }

    ts->sni_stats = memoryAllocateZero(sizeof(*ts->sni_stats) * (size_t) ts->snis_count);
    ts->sni_weight_total = 0;

    for (uint32_t i = 0; i < ts->snis_count; ++i)
    {
        atomicStoreRelaxed(&ts->sni_stats[i].healthy, 1);
        atomicStoreRelaxed(&ts->sni_stats[i].rtt_ema_ms, kTlsClientUnknownRttMs);
        ts->sni_stats[i].weight = kTlsClientDefaultSniWeight;
        ts->sni_weight_total += kTlsClientDefaultSniWeight;
    }

    return true;
}

void tlsclientFreeSniSettings(tlsclient_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    if (ts->snis != NULL)
    {
        for (uint32_t i = 0; i < ts->snis_count; ++i)
        {
            memoryFree(ts->snis[i]);
        }
        memoryFree(ts->snis);
    }

    memoryFree(ts->sni_stats);

    ts->snis          = NULL;
    ts->snis_count    = 0;
    ts->sni_stats     = NULL;
    ts->sni_weight_total = 0;
}

bool tlsclientParseSniSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    const cJSON *sni_field  = cJSON_GetObjectItemCaseSensitive(settings, "sni");
    const cJSON *snis_field = cJSON_GetObjectItemCaseSensitive(settings, "snis");

    if (sni_field != NULL && snis_field != NULL)
    {
        LOGF("JSON Error: TlsClient->settings must use either \"sni\" or \"snis\", not both");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    if (snis_field != NULL)
    {
        if (! cJSON_IsArray(snis_field) || cJSON_GetArraySize(snis_field) <= 0)
        {
            LOGF("JSON Error: TlsClient->settings->snis (array field) : expected one or more SNIs");
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }

        const int count = cJSON_GetArraySize(snis_field);
        ts->snis_count = (uint32_t) count;
        ts->snis       = memoryAllocateZero(sizeof(*ts->snis) * (size_t) ts->snis_count);

        int          index = 0;
        const cJSON *item  = NULL;
        cJSON_ArrayForEach(item, snis_field)
        {
            if (! tlsclientLoadSniString(&ts->snis[index], item, "TlsClient->settings->snis[]"))
            {
                tlsclientDestroyAfterSniConfigError(ts, t);
                return false;
            }
            ++index;
        }
    }
    else
    {
        if (sni_field == NULL)
        {
            LOGF("JSON Error: TlsClient->settings must provide either \"sni\" or \"snis\"");
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }

        ts->snis_count = 1;
        ts->snis       = memoryAllocateZero(sizeof(*ts->snis));
        if (! tlsclientLoadSniString(&ts->snis[0], sni_field, "TlsClient->settings->sni"))
        {
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }
    }

    return tlsclientAllocateSniStats(ts);
}

static bool tlsclientParseSniSelectionName(const char *name, tlsclient_sni_selection_e *out)
{
    if (stricmp(name, "fixed") == 0)
    {
        *out = kTlsClientSniSelectionFixed;
        return true;
    }

    if (stricmp(name, "round-robin") == 0)
    {
        *out = kTlsClientSniSelectionRoundRobin;
        return true;
    }

    if (stricmp(name, "random") == 0)
    {
        *out = kTlsClientSniSelectionRandom;
        return true;
    }

    if (stricmp(name, "race") == 0)
    {
        *out = kTlsClientSniSelectionRace;
        return true;
    }

    if (stricmp(name, "healthy-only") == 0)
    {
        *out = kTlsClientSniSelectionHealthyOnly;
        return true;
    }

    if (stricmp(name, "least-rtt") == 0)
    {
        *out = kTlsClientSniSelectionLeastRtt;
        return true;
    }

    if (stricmp(name, "weighted-round-robin") == 0)
    {
        *out = kTlsClientSniSelectionWeightedRoundRobin;
        return true;
    }

    return false;
}

bool tlsclientParseSniSelectionSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    char *selection_name = NULL;

    if (getStringFromJsonObject(&selection_name, settings, "sni-selection"))
    {
        if (! tlsclientParseSniSelectionName(selection_name, &ts->sni_selection))
        {
            LOGF("JSON Error: TlsClient->settings->sni-selection (string field) : unsupported value \"%s\"",
                 selection_name);
            memoryFree(selection_name);
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }
        memoryFree(selection_name);
    }
    else if (ts->snis_count > 1)
    {
        ts->sni_selection = kTlsClientSniSelectionRoundRobin;
    }
    else
    {
        ts->sni_selection = kTlsClientSniSelectionFixed;
    }

    int race_tries      = (int) ts->snis_count;
    int race_timeout_ms = kTlsClientDefaultRaceTimeoutMs;

    getIntFromJsonObjectOrDefault(&race_tries, settings, "race-tries", race_tries);
    getIntFromJsonObjectOrDefault(&race_timeout_ms, settings, "race-timeout-ms", race_timeout_ms);

    if (race_tries < 1)
    {
        LOGF("JSON Error: TlsClient->settings->race-tries (integer field) : must be >= 1");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    if (race_timeout_ms <= 0)
    {
        LOGF("JSON Error: TlsClient->settings->race-timeout-ms (integer field) : must be > 0");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    ts->race_tries      = (uint32_t) race_tries;
    ts->race_timeout_ms = (uint32_t) race_timeout_ms;

    if (ts->race_tries > ts->snis_count)
    {
        ts->race_tries = ts->snis_count;
    }

    return true;
}

static bool tlsclientParseSniWeights(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    const cJSON *weights = cJSON_GetObjectItemCaseSensitive(settings, "sni-weights");
    if (weights == NULL)
    {
        return true;
    }

    if (! cJSON_IsArray(weights) || (uint32_t) cJSON_GetArraySize(weights) != ts->snis_count)
    {
        LOGF("JSON Error: TlsClient->settings->sni-weights (array field) : length must match the configured SNI count");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    ts->sni_weight_total = 0;

    int          index = 0;
    const cJSON *item  = NULL;
    cJSON_ArrayForEach(item, weights)
    {
        if (! cJSON_IsNumber(item) || item->valueint < 1)
        {
            LOGF("JSON Error: TlsClient->settings->sni-weights[] (integer field) : expected a positive integer");
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }

        uint64_t total = (uint64_t) ts->sni_weight_total + (uint32_t) item->valueint;
        if (total > UINT32_MAX)
        {
            LOGF("JSON Error: TlsClient->settings->sni-weights (array field) : total weight is too large");
            tlsclientDestroyAfterSniConfigError(ts, t);
            return false;
        }

        ts->sni_stats[index].weight = (uint32_t) item->valueint;
        ts->sni_weight_total        = (uint32_t) total;
        ++index;
    }

    return true;
}

bool tlsclientParseSniHealthSettings(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    int max_failures       = kTlsClientDefaultSniMaxConsecutiveFailures;
    int probe_interval_ms  = 0;
    int min_unused_per_sni = 0;

    getIntFromJsonObjectOrDefault(&max_failures, settings, "sni-max-consecutive-failures", max_failures);
    getIntFromJsonObjectOrDefault(&probe_interval_ms, settings, "sni-probe-interval-ms", probe_interval_ms);
    getIntFromJsonObjectOrDefault(&min_unused_per_sni, settings, "min-unused-per-sni", min_unused_per_sni);

    if (max_failures < 1)
    {
        LOGF("JSON Error: TlsClient->settings->sni-max-consecutive-failures (integer field) : must be >= 1");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    if (probe_interval_ms < 0)
    {
        LOGF("JSON Error: TlsClient->settings->sni-probe-interval-ms (integer field) : must be >= 0");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    if (min_unused_per_sni < 0)
    {
        LOGF("JSON Error: TlsClient->settings->min-unused-per-sni (integer field) : must be >= 0");
        tlsclientDestroyAfterSniConfigError(ts, t);
        return false;
    }

    ts->sni_max_consecutive_failures = (uint32_t) max_failures;
    ts->sni_probe_interval_ms        = (uint32_t) probe_interval_ms;
    ts->min_unused_per_sni           = (uint32_t) min_unused_per_sni;

    if (ts->sni_probe_interval_ms > 0)
    {
        LOGW("TlsClient: active SNI probes are not started by this tunnel; passive health tracking is used");
    }

    return tlsclientParseSniWeights(ts, settings, t);
}

static bool tlsclientSniIsHealthy(const tlsclient_tstate_t *ts, uint32_t index)
{
    return ts->sni_stats == NULL || index >= ts->snis_count || atomicLoadRelaxed(&ts->sni_stats[index].healthy) != 0;
}

static bool tlsclientSniBelowQuota(const tlsclient_tstate_t *ts, uint32_t index)
{
    return ts->min_unused_per_sni == 0 || ts->sni_stats == NULL || index >= ts->snis_count ||
           (uint32_t) atomicLoadRelaxed(&ts->sni_stats[index].active_lines) < ts->min_unused_per_sni;
}

static bool tlsclientSniAllowed(const tlsclient_tstate_t *ts, uint32_t index, bool require_healthy, bool require_quota)
{
    if (require_healthy && ! tlsclientSniIsHealthy(ts, index))
    {
        return false;
    }

    if (require_quota && ! tlsclientSniBelowQuota(ts, index))
    {
        return false;
    }

    return true;
}

static uint32_t tlsclientCountCandidates(const tlsclient_tstate_t *ts, bool require_healthy, bool require_quota)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < ts->snis_count; ++i)
    {
        if (tlsclientSniAllowed(ts, i, require_healthy, require_quota))
        {
            ++count;
        }
    }

    return count;
}

static void tlsclientRelaxEmptyFilters(const tlsclient_tstate_t *ts, bool *require_healthy, bool *require_quota)
{
    if (*require_healthy && tlsclientCountCandidates(ts, true, *require_quota) == 0)
    {
        *require_healthy = false;
        LOGW("TlsClient: all configured SNIs are unhealthy, falling back to the full SNI pool");
    }

    if (*require_quota && tlsclientCountCandidates(ts, *require_healthy, true) == 0)
    {
        *require_quota = false;
    }
}

static uint32_t tlsclientPickRoundRobinIndex(tlsclient_tstate_t *ts, bool require_healthy, bool require_quota)
{
    uint32_t start = (uint32_t) atomic_fetch_add(&ts->sni_round_index, 1);

    for (uint32_t offset = 0; offset < ts->snis_count; ++offset)
    {
        uint32_t index = (start + offset) % ts->snis_count;
        if (tlsclientSniAllowed(ts, index, require_healthy, require_quota))
        {
            return index;
        }
    }

    return start % ts->snis_count;
}

static uint32_t tlsclientPickRandomIndex(tlsclient_tstate_t *ts, bool require_healthy, bool require_quota)
{
    uint32_t start = (uint32_t) (fastRand64() % ts->snis_count);

    for (uint32_t offset = 0; offset < ts->snis_count; ++offset)
    {
        uint32_t index = (start + offset) % ts->snis_count;
        if (tlsclientSniAllowed(ts, index, require_healthy, require_quota))
        {
            return index;
        }
    }

    return start;
}

static uint32_t tlsclientPickLeastRttIndex(tlsclient_tstate_t *ts, bool require_healthy, bool require_quota)
{
    uint32_t start      = (uint32_t) atomic_fetch_add(&ts->sni_round_index, 1);
    uint32_t best_index = start % ts->snis_count;
    uint32_t best_rtt   = UINT32_MAX;
    bool     found      = false;

    for (uint32_t offset = 0; offset < ts->snis_count; ++offset)
    {
        uint32_t index = (start + offset) % ts->snis_count;
        if (! tlsclientSniAllowed(ts, index, require_healthy, require_quota))
        {
            continue;
        }

        uint32_t rtt = (uint32_t) atomicLoadRelaxed(&ts->sni_stats[index].rtt_ema_ms);
        if (! found || rtt < best_rtt)
        {
            best_index = index;
            best_rtt   = rtt;
            found      = true;
        }
    }

    return found ? best_index : start % ts->snis_count;
}

static uint32_t tlsclientPickWeightedRoundRobinIndex(tlsclient_tstate_t *ts, bool require_healthy, bool require_quota)
{
    uint32_t eligible_weight = 0;

    for (uint32_t i = 0; i < ts->snis_count; ++i)
    {
        if (tlsclientSniAllowed(ts, i, require_healthy, require_quota))
        {
            eligible_weight += ts->sni_stats[i].weight;
        }
    }

    if (eligible_weight == 0)
    {
        return tlsclientPickRoundRobinIndex(ts, false, false);
    }

    uint32_t slot = (uint32_t) atomic_fetch_add(&ts->sni_weight_index, 1) % eligible_weight;
    uint32_t sum  = 0;

    for (uint32_t i = 0; i < ts->snis_count; ++i)
    {
        if (! tlsclientSniAllowed(ts, i, require_healthy, require_quota))
        {
            continue;
        }

        sum += ts->sni_stats[i].weight;
        if (slot < sum)
        {
            return i;
        }
    }

    return ts->snis_count - 1;
}

static uint32_t tlsclientPickSniIndex(tlsclient_tstate_t *ts, line_t *l)
{
    discard l;

    if (ts->snis_count <= 1)
    {
        return 0;
    }

    bool require_healthy = ts->sni_selection == kTlsClientSniSelectionHealthyOnly ||
                           ts->sni_selection == kTlsClientSniSelectionLeastRtt;
    bool require_quota = ts->min_unused_per_sni > 0 && ts->sni_selection != kTlsClientSniSelectionFixed;

    tlsclientRelaxEmptyFilters(ts, &require_healthy, &require_quota);

    switch (ts->sni_selection)
    {
    case kTlsClientSniSelectionFixed:
        return 0;
    case kTlsClientSniSelectionRoundRobin:
    case kTlsClientSniSelectionHealthyOnly:
        return tlsclientPickRoundRobinIndex(ts, require_healthy, require_quota);
    case kTlsClientSniSelectionRandom:
        return tlsclientPickRandomIndex(ts, require_healthy, require_quota);
    case kTlsClientSniSelectionLeastRtt:
        return tlsclientPickLeastRttIndex(ts, require_healthy, require_quota);
    case kTlsClientSniSelectionWeightedRoundRobin:
        return tlsclientPickWeightedRoundRobinIndex(ts, require_healthy, require_quota);
    case kTlsClientSniSelectionRace:
    default:
        return tlsclientPickRoundRobinIndex(ts, false, require_quota);
    }
}

void tlsclientSelectSniForLine(tlsclient_tstate_t *ts, tlsclient_lstate_t *ls, line_t *l)
{
    ls->selected_sni_index = tlsclientPickSniIndex(ts, l);
    ls->selected_sni       = ts->snis[ls->selected_sni_index];
}

static bool tlsclientIndexAlreadySelected(const uint32_t *indices, uint32_t count, uint32_t index)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (indices[i] == index)
        {
            return true;
        }
    }

    return false;
}

uint32_t tlsclientSelectRaceSniIndices(tlsclient_tstate_t *ts, uint32_t *indices, uint32_t max_indices)
{
    if (ts->snis_count == 0 || indices == NULL || max_indices == 0)
    {
        return 0;
    }

    uint32_t limit = ts->race_tries;
    if (limit > max_indices)
    {
        limit = max_indices;
    }
    if (limit > ts->snis_count)
    {
        limit = ts->snis_count;
    }

    bool require_healthy = tlsclientCountCandidates(ts, true, false) > 0;
    bool require_quota   = ts->min_unused_per_sni > 0 && tlsclientCountCandidates(ts, require_healthy, true) > 0;
    uint32_t selected    = 0;
    uint32_t start       = (uint32_t) atomic_fetch_add(&ts->sni_round_index, limit);

    for (uint32_t offset = 0; offset < ts->snis_count && selected < limit; ++offset)
    {
        uint32_t index = (start + offset) % ts->snis_count;
        if (tlsclientSniAllowed(ts, index, require_healthy, require_quota))
        {
            indices[selected++] = index;
        }
    }

    for (uint32_t offset = 0; offset < ts->snis_count && selected < limit; ++offset)
    {
        uint32_t index = (start + offset) % ts->snis_count;
        if (! tlsclientIndexAlreadySelected(indices, selected, index))
        {
            indices[selected++] = index;
        }
    }

    return selected;
}

static void tlsclientUpdateRttEma(tlsclient_sni_stat_t *stat, uint32_t sample_ms)
{
    uint32_t prev = (uint32_t) atomicLoadRelaxed(&stat->rtt_ema_ms);

    if (prev == kTlsClientUnknownRttMs)
    {
        atomicStoreRelaxed(&stat->rtt_ema_ms, sample_ms);
        return;
    }

    atomicStoreRelaxed(&stat->rtt_ema_ms, (prev * 7U + sample_ms) / 8U);
}

void tlsclientRecordSniSuccessForLine(tunnel_t *t, tlsclient_lstate_t *ls)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);

    if (ts->sni_stats == NULL || ls->selected_sni == NULL || ls->selected_sni_index >= ts->snis_count ||
        ls->sni_success_recorded)
    {
        return;
    }

    uint32_t rtt_ms = 0;
    uint64_t now_ms = getTimeOfDayMS();
    if (ls->handshake_start_ms > 0 && now_ms >= ls->handshake_start_ms)
    {
        rtt_ms = (uint32_t) (now_ms - ls->handshake_start_ms);
    }

    tlsclient_sni_stat_t *stat = &ts->sni_stats[ls->selected_sni_index];
    atomic_fetch_add(&stat->successes, 1);
    atomicStoreRelaxed(&stat->consecutive_failures, 0);
    atomicStoreRelaxed(&stat->healthy, 1);
    tlsclientUpdateRttEma(stat, rtt_ms);

    ls->sni_success_recorded = true;

    if (! ls->sni_active_tracked && ls->role != kTlsClientLineRoleRaceMain)
    {
        atomic_fetch_add(&stat->active_lines, 1);
        ls->sni_active_tracked = true;
    }
}

void tlsclientRecordSniFailureForLine(tunnel_t *t, tlsclient_lstate_t *ls)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);

    if (ts->sni_stats == NULL || ls->selected_sni == NULL || ls->selected_sni_index >= ts->snis_count ||
        ls->handshake_completed || ls->sni_failure_recorded)
    {
        return;
    }

    tlsclient_sni_stat_t *stat = &ts->sni_stats[ls->selected_sni_index];
    uint32_t consecutive = (uint32_t) atomic_fetch_add(&stat->consecutive_failures, 1) + 1U;

    atomic_fetch_add(&stat->failures, 1);
    ls->sni_failure_recorded = true;

    if (consecutive >= ts->sni_max_consecutive_failures)
    {
        atomicStoreRelaxed(&stat->healthy, 0);
        LOGW("TlsClient: marking SNI \"%s\" unhealthy after %u consecutive TLS failures",
             ts->snis[ls->selected_sni_index],
             consecutive);
    }
}

void tlsclientReleaseActiveSniLine(tunnel_t *t, tlsclient_lstate_t *ls)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);

    if (ts->sni_stats == NULL || ! ls->sni_active_tracked || ls->selected_sni_index >= ts->snis_count)
    {
        return;
    }

    tlsclient_sni_stat_t *stat = &ts->sni_stats[ls->selected_sni_index];
    atomic_uint value = atomicLoadRelaxed(&stat->active_lines);
    if (value > 0)
    {
        atomic_fetch_sub(&stat->active_lines, 1);
    }

    ls->sni_active_tracked = false;
}
