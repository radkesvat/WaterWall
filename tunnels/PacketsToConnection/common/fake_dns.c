#include "structure.h"

#include "loggers/dns_logger.h"

enum
{
    kPtcDnsHeaderLen          = 12,
    kPtcDnsMaxQuestions       = 32,
    kPtcDnsAnswerALen         = 16,
    kPtcDnsTypeA              = 1,
    kPtcDnsClassIn            = 1,
    kPtcFakeDnsDefaultPort    = 53,
    kPtcFakeDnsDefaultTtl     = 1,
    kPtcFakeDnsDefaultRecords = 10000,

    kPtcFakeDnsMaxTtl = INT32_MAX
};

typedef struct ptc_dns_answer_s
{
    uint32_t fake_addr_network;
    uint16_t name_offset;
} ptc_dns_answer_t;

/* One fully parsed question, staged before any cache state is touched. */
typedef struct ptc_dns_question_s
{
    char     domain[256];
    uint16_t name_offset;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t  domain_len;
    uint8_t  mapping_index;
} ptc_dns_question_t;

typedef struct ptc_dns_mapping_s
{
    ptc_fake_dns_entry_t *entry;
    ptc_fake_dns_entry_t *victim;
    const char           *domain;
    uint8_t               domain_len;
    bool                  staged;
    bool                  inserted;
} ptc_dns_mapping_t;

typedef struct ptc_fake_dns_geometry_s
{
    size_t  record_bytes;
    isize_t map_capacity;
} ptc_fake_dns_geometry_t;

static bool ptcFakeDnsComputeGeometry(uint32_t cache_size, ptc_fake_dns_geometry_t *out)
{
    size_t record_bytes;
    if (out == NULL || cache_size == 0 || cache_size > kPtcFakeDnsMaxRecords ||
        ! memoryTryComputeArraySize(cache_size, sizeof(ptc_fake_dns_entry_t *), &record_bytes))
    {
        return false;
    }

    const uint64_t map_capacity = (uint64_t) cache_size + kPtcDnsMaxQuestions;
    if (map_capacity > PTRDIFF_MAX || map_capacity > (UINT64_MAX - 19U) / 5U)
    {
        return false;
    }

    /* STC rounds float(capacity / 0.8) + 4 to the next power of two. */
    const uint64_t raw_buckets   = ((map_capacity * 5U) + 3U) / 4U + 4U;
    uint64_t       largest_power = 1;
    while (largest_power <= (uint64_t) PTRDIFF_MAX / 2U)
    {
        largest_power *= 2U;
    }
    if (raw_buckets > largest_power)
    {
        return false;
    }

    *out = (ptc_fake_dns_geometry_t) {
        .record_bytes = record_bytes,
        .map_capacity = (isize_t) map_capacity,
    };
    return true;
}

static char *ptcFakeDnsDuplicateString(const char *value, uint8_t len)
{
    char *out = memoryAllocate((size_t) len + 1U);

    if (UNLIKELY(out == NULL))
    {
        return NULL;
    }

    memoryCopy(out, value, len);
    out[len] = '\0';
    return out;
}

static uint16_t ptcDnsRead16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8U) | (uint16_t) p[1]);
}

static void ptcDnsWrite16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8U);
    p[1] = (uint8_t) value;
}

static void ptcDnsWrite32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t) (value >> 24U);
    p[1] = (uint8_t) (value >> 16U);
    p[2] = (uint8_t) (value >> 8U);
    p[3] = (uint8_t) value;
}

static bool ptcDnsReadQuestionName(const uint8_t *packet, uint32_t packet_len, uint32_t *offset, char *domain,
                                   uint8_t *domain_len)
{
    uint32_t pos = *offset;
    uint32_t out = 0;

    while (true)
    {
        if (pos >= packet_len)
        {
            return false;
        }

        uint8_t label_len = packet[pos++];
        if (label_len == 0)
        {
            break;
        }

        if ((label_len & 0xC0U) != 0 || label_len > 63U || pos + label_len > packet_len)
        {
            return false;
        }

        if (out != 0)
        {
            if (out >= 253U)
            {
                return false;
            }
            domain[out++] = '.';
        }

        if (out + label_len > 253U)
        {
            return false;
        }

        for (uint8_t i = 0; i < label_len; ++i)
        {
            domain[out++] = asciiLower((char) packet[pos + i]);
        }
        pos += label_len;
    }

    if (out == 0 || out > UINT8_MAX)
    {
        return false;
    }

    domain[out] = '\0';
    *domain_len = (uint8_t) out;
    *offset     = pos;
    return true;
}

static void ptcFakeDnsLruUnlink(ptc_fake_dns_t *dns, ptc_fake_dns_entry_t *entry)
{
    if (entry->prev != NULL)
    {
        entry->prev->next = entry->next;
    }
    else
    {
        dns->lru_head = entry->next;
    }

    if (entry->next != NULL)
    {
        entry->next->prev = entry->prev;
    }
    else
    {
        dns->lru_tail = entry->prev;
    }

    entry->prev = NULL;
    entry->next = NULL;
}

static void ptcFakeDnsLruPushTail(ptc_fake_dns_t *dns, ptc_fake_dns_entry_t *entry)
{
    entry->prev = dns->lru_tail;
    entry->next = NULL;

    if (dns->lru_tail != NULL)
    {
        dns->lru_tail->next = entry;
    }
    else
    {
        dns->lru_head = entry;
    }

    dns->lru_tail = entry;
}

static void ptcFakeDnsTouch(ptc_fake_dns_t *dns, ptc_fake_dns_entry_t *entry)
{
    if (dns->lru_tail == entry)
    {
        return;
    }

    ptcFakeDnsLruUnlink(dns, entry);
    ptcFakeDnsLruPushTail(dns, entry);
}

static ptc_fake_dns_entry_t *ptcFakeDnsFindByName(ptc_fake_dns_t *dns, const char *domain, uint8_t domain_len)
{
    ptc_fake_dns_name_key_t      key = {.name = domain, .len = domain_len};
    ptc_fake_dns_name_map_t_iter it  = ptc_fake_dns_name_map_t_find(&dns->names, key);

    if (it.ref == ptc_fake_dns_name_map_t_end(&dns->names).ref)
    {
        return NULL;
    }

    return it.ref->second;
}

static bool ptcFakeDnsEntryIsPinned(const ptc_dns_mapping_t *mappings, uint8_t mapping_count,
                                    const ptc_fake_dns_entry_t *entry)
{
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        if (! mappings[i].staged && mappings[i].entry == entry)
        {
            return true;
        }
    }
    return false;
}

static void ptcFakeDnsDiscardStagedMappings(ptc_fake_dns_t *dns, ptc_dns_mapping_t *mappings, uint8_t mapping_count)
{
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }
        if (mapping->entry == NULL)
        {
            continue;
        }
        if (mapping->inserted)
        {
            const ptc_fake_dns_name_key_t key = {
                .name = mapping->entry->domain,
                .len  = mapping->entry->domain_len,
            };
            discard ptc_fake_dns_name_map_t_erase(&dns->names, key);
        }
        memoryFree(mapping->entry->domain);
        memoryFree(mapping->entry);
        mapping->entry    = NULL;
        mapping->inserted = false;
    }
}

/*
 * Resolve every A/IN question as one cache transaction.
 *
 * No existing key, record, or LRU link is changed until every new entry and
 * domain has been allocated and every new key is resident in the pre-reserved
 * map. A failed staged insertion erases only staged keys. Existing entries used
 * by this response are pinned while victims are selected, so every emitted fake
 * address remains reverse-resolvable after the whole reply is committed.
 */
static bool ptcFakeDnsCommitQuestions(ptc_fake_dns_t *dns, ptc_dns_question_t *questions, int question_count,
                                      ptc_dns_mapping_t *mappings, uint8_t *mapping_count_out)
{
    uint8_t mapping_count = 0;

    for (int question_index = 0; question_index < question_count; ++question_index)
    {
        ptc_dns_question_t *question = &questions[question_index];

        question->mapping_index = UINT8_MAX;
        if (question->qtype != kPtcDnsTypeA || question->qclass != kPtcDnsClassIn)
        {
            continue;
        }

        uint8_t mapping_index = 0;
        for (; mapping_index < mapping_count; ++mapping_index)
        {
            if (mappings[mapping_index].domain_len == question->domain_len &&
                memoryCompare(mappings[mapping_index].domain, question->domain, question->domain_len) == 0)
            {
                break;
            }
        }

        if (mapping_index == mapping_count)
        {
            ptc_fake_dns_entry_t *existing = ptcFakeDnsFindByName(dns, question->domain, question->domain_len);
            mappings[mapping_count]        = (ptc_dns_mapping_t) {
                       .entry      = existing,
                       .domain     = question->domain,
                       .domain_len = question->domain_len,
                       .staged     = existing == NULL,
            };
            ++mapping_count;
        }
        question->mapping_index = mapping_index;
    }

    *mapping_count_out = mapping_count;

    /* Deterministic capacity policy: answer none unless every unique name can coexist. */
    if (mapping_count > dns->capacity)
    {
        return false;
    }

#ifndef NDEBUG
    uint8_t staged_count = 0;
#endif
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }
#ifndef NDEBUG
        ++staged_count;
#endif

        char *domain = ptcFakeDnsDuplicateString(mapping->domain, mapping->domain_len);
        if (UNLIKELY(domain == NULL))
        {
            ptcFakeDnsDiscardStagedMappings(dns, mappings, mapping_count);
            return false;
        }

        mapping->entry = memoryAllocateZero(sizeof(*mapping->entry));
        if (UNLIKELY(mapping->entry == NULL))
        {
            memoryFree(domain);
            ptcFakeDnsDiscardStagedMappings(dns, mappings, mapping_count);
            return false;
        }
        mapping->entry->domain     = domain;
        mapping->entry->domain_len = mapping->domain_len;
    }

    const uint32_t        free_count    = dns->capacity - dns->used;
    uint32_t              free_index    = dns->used;
    uint32_t              assigned_free = 0;
    ptc_fake_dns_entry_t *victim        = dns->lru_head;

    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }

        if (assigned_free < free_count)
        {
            mapping->entry->index = free_index++;
            ++assigned_free;
        }
        else
        {
            while (victim != NULL && ptcFakeDnsEntryIsPinned(mappings, mapping_count, victim))
            {
                victim = victim->next;
            }
            if (UNLIKELY(victim == NULL))
            {
                ptcFakeDnsDiscardStagedMappings(dns, mappings, mapping_count);
                return false;
            }
            mapping->victim       = victim;
            mapping->entry->index = victim->index;
            victim                = victim->next;
        }
        mapping->entry->fake_addr_network = lwip_htonl(dns->network_host | mapping->entry->index);
    }

#ifndef NDEBUG
    /* The map was reserved for capacity + max questions during configuration. */
    assert(ptc_fake_dns_name_map_t_capacity(&dns->names) >= (isize_t) (dns->used + staged_count));
#endif
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }
        const ptc_fake_dns_name_key_t key = {
            .name = mapping->entry->domain,
            .len  = mapping->entry->domain_len,
        };
        if (UNLIKELY(! ptc_fake_dns_name_map_t_insert(&dns->names, key, mapping->entry).inserted))
        {
            ptcFakeDnsDiscardStagedMappings(dns, mappings, mapping_count);
            return false;
        }
        mapping->inserted = true;
    }

    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }
        if (mapping->victim != NULL)
        {
            const ptc_fake_dns_name_key_t old_key = {
                .name = mapping->victim->domain,
                .len  = mapping->victim->domain_len,
            };
            discard ptc_fake_dns_name_map_t_erase(&dns->names, old_key);
            ptcFakeDnsLruUnlink(dns, mapping->victim);
            memoryFree(mapping->victim->domain);
            memoryFree(mapping->victim);
        }
        else
        {
            ++dns->used;
        }

        dns->records[mapping->entry->index] = mapping->entry;
        ptcFakeDnsLruPushTail(dns, mapping->entry);
        mapping->inserted = false;
    }

    /* Apply successful lookup touches only after the transaction cannot fail. */
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        if (! mappings[i].staged)
        {
            ptcFakeDnsTouch(dns, mappings[i].entry);
        }
    }
    return true;
}

static ptc_fake_dns_entry_t *ptcFakeDnsLookupByIp(ptc_fake_dns_t *dns, const ip4_addr_t *ip)
{
    if (! dns->enabled || dns->records == NULL)
    {
        return NULL;
    }

    uint32_t host = lwip_ntohl(ip->addr);
    if ((host & dns->netmask_host) != dns->network_host)
    {
        return NULL;
    }

    uint32_t index = host & ~dns->netmask_host;
    if (index >= dns->capacity)
    {
        return NULL;
    }

    ptc_fake_dns_entry_t *entry = dns->records[index];
    if (entry == NULL || entry->fake_addr_network != ip->addr)
    {
        return NULL;
    }

    ptcFakeDnsTouch(dns, entry);
    return entry;
}

/*
 * Parses and validates the whole question section without touching the cache.
 *
 * The parse used to allocate a mapping per question as it went, so a query whose
 * second question was truncated still inserted the first - and against a full
 * cache that insertion evicts a live mapping by LRU. A query that receives no
 * answer at all must not be able to change what any other name resolves to.
 *
 * Returns the number of parsed questions, or -1. `end_offset` is where the
 * question section ends, which is also where answers start.
 */
static int ptcFakeDnsParseQuestions(const uint8_t *query, uint32_t query_len, ptc_dns_question_t *questions,
                                    uint32_t *end_offset)
{
    uint32_t offset = kPtcDnsHeaderLen;

    if (query_len < kPtcDnsHeaderLen)
    {
        return -1;
    }

    const uint16_t query_flags = ptcDnsRead16(query + 2);
    if ((query_flags & 0x8000U) != 0)
    {
        return -1;
    }

    const uint16_t question_count = ptcDnsRead16(query + 4);
    if (question_count == 0 || question_count > kPtcDnsMaxQuestions)
    {
        return -1;
    }

    for (uint16_t i = 0; i < question_count; ++i)
    {
        ptc_dns_question_t *question    = &questions[i];
        const uint32_t      name_offset = offset;

        question->domain_len = 0;
        if (name_offset > 0x3FFFU ||
            ! ptcDnsReadQuestionName(query, query_len, &offset, question->domain, &question->domain_len))
        {
            return -1;
        }

        if (offset + 4U > query_len)
        {
            return -1;
        }

        question->qtype       = ptcDnsRead16(query + offset);
        question->qclass      = ptcDnsRead16(query + offset + 2U);
        question->name_offset = (uint16_t) name_offset;
        offset += 4U;
    }

    *end_offset = offset;
    return (int) question_count;
}

static int ptcFakeDnsBuildResponse(ptc_tstate_t *ts, const uint8_t *query, uint32_t query_len, uint8_t *response,
                                   uint32_t response_capacity)
{
    ptc_dns_answer_t   answers[kPtcDnsMaxQuestions];
    ptc_dns_mapping_t  mappings[kPtcDnsMaxQuestions] = {0};
    ptc_dns_question_t questions[kPtcDnsMaxQuestions];
    uint16_t           answer_count = 0;
    uint32_t           offset       = 0;

    const int question_count = ptcFakeDnsParseQuestions(query, query_len, questions, &offset);
    if (question_count < 0)
    {
        return -1;
    }

    /*
     * Whether the answers fit is decided before the first mapping is created,
     * for the same reason: an over-capacity response used to be refused after
     * every question had already touched the cache.
     */
    const uint32_t dns_len = offset + ((uint32_t) question_count * kPtcDnsAnswerALen);
    if (dns_len > response_capacity)
    {
        return -1;
    }

    uint8_t mapping_count = 0;
    if (ptcFakeDnsCommitQuestions(&ts->fake_dns, questions, question_count, mappings, &mapping_count))
    {
        for (int i = 0; i < question_count; ++i)
        {
            const ptc_dns_question_t *question = &questions[i];

            if (question->mapping_index != UINT8_MAX)
            {
                assert(question->mapping_index < mapping_count);
                const uint32_t fake_addr = mappings[question->mapping_index].entry->fake_addr_network;
                assert(fake_addr != 0);
                answers[answer_count++] =
                    (ptc_dns_answer_t) {.fake_addr_network = fake_addr, .name_offset = question->name_offset};
            }
        }
    }

    /* Only answered questions carry an answer record, so this cannot exceed dns_len. */
    const uint32_t answered_len = offset + ((uint32_t) answer_count * kPtcDnsAnswerALen);
    assert(answered_len <= dns_len);
    const uint16_t query_flags = ptcDnsRead16(query + 2);

    memoryCopy(response, query, offset);

    uint16_t response_flags = (uint16_t) (0x8000U | 0x0080U | (query_flags & 0x7900U));
    ptcDnsWrite16(response + 2, response_flags);
    ptcDnsWrite16(response + 6, answer_count);
    ptcDnsWrite16(response + 8, 0);
    ptcDnsWrite16(response + 10, 0);

    uint8_t *answer = response + offset;
    for (uint16_t i = 0; i < answer_count; ++i)
    {
        answer[0] = (uint8_t) (0xC0U | (answers[i].name_offset >> 8U));
        answer[1] = (uint8_t) answers[i].name_offset;
        ptcDnsWrite16(answer + 2, kPtcDnsTypeA);
        ptcDnsWrite16(answer + 4, kPtcDnsClassIn);
        ptcDnsWrite32(answer + 6, ts->fake_dns.ttl);
        ptcDnsWrite16(answer + 10, 4);
        memoryCopy(answer + 12, &answers[i].fake_addr_network, sizeof(answers[i].fake_addr_network));
        answer += kPtcDnsAnswerALen;
    }

    return (int) answered_len;
}

static bool ptcFakeDnsParseIpv4(ip4_addr_t *out, const char *value, const char *json_path)
{
    ip_addr_t ip;

    if (! ipaddr_aton(value, &ip) || ! ipAddrIsV4(&ip))
    {
        LOGF("JSON Error: %s must be a valid IPv4 address", json_path);
        return false;
    }

    *out = ip.u_addr.ip4;
    return true;
}

/*
 * Present but invalid is an error, not a default.
 *
 * getStringFromJsonObjectOrDefault() answers the same way for an omitted field
 * and for one of the wrong type, so `"address": 5` used to configure 198.18.0.2
 * and never say so.
 */
bool ptcLoadOptionalInteger(const cJSON *settings, const char *key, int64_t minimum, int64_t maximum,
                            int64_t *value_inout, const char *json_path)
{
    int64_t                   parsed = 0;
    const json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, minimum, maximum, &parsed);

    if (status == kJsonValueMissing)
    {
        return true;
    }

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s (int field) : expected a whole number between %lld and %lld",
             json_path,
             (long long) minimum,
             (long long) maximum);
        return false;
    }

    *value_inout = parsed;
    return true;
}

static bool ptcFakeDnsLoadOptionalBoolean(const cJSON *settings, const char *key, bool *value_inout,
                                          const char *json_path)
{
    const json_value_status_t status = jsonGetObjectBoolean(settings, key, value_inout);

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s (bool field) : expected true or false", json_path);
        return false;
    }
    return true;
}

static bool ptcFakeDnsLoadIpv4Setting(ip4_addr_t *out, const cJSON *settings, const char *key, const char *def,
                                      const char *json_path)
{
    const char               *value  = def;
    const json_value_status_t status = jsonGetObjectNonEmptyString(settings, key, &value);

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s must be a non-empty string", json_path);
        return false;
    }

    return ptcFakeDnsParseIpv4(out, value, json_path);
}

static bool ptcFakeDnsIsAliasName(const char *name)
{
    return name != NULL && (stringCompare(name, "fake-dns") == 0 || stringCompare(name, "fake_dns") == 0 ||
                            stringCompare(name, "mapdns") == 0);
}

static uint32_t ptcFakeDnsFieldBit(const char *name)
{
    static const char *const fields[] = {
        "enabled",
        "address",
        "network",
        "netmask",
        "port",
        "ttl",
        "cache-size",
    };

    if (name == NULL)
    {
        return 0;
    }
    for (uint32_t index = 0; index < ARRAY_SIZE(fields); ++index)
    {
        if (stringCompare(name, fields[index]) == 0)
        {
            return UINT32_C(1) << index;
        }
    }
    return 0;
}

bool ptcFakeDnsLoadSettings(ptc_tstate_t *ts, const cJSON *settings)
{
    if (settings == NULL)
    {
        return true;
    }

    const cJSON *fake_dns        = NULL;
    unsigned int aliases_present = 0;
    const cJSON *member;
    cJSON_ArrayForEach(member, settings)
    {
        if (! ptcFakeDnsIsAliasName(member->string))
        {
            continue;
        }
        ++aliases_present;
        if (fake_dns == NULL)
        {
            fake_dns = member;
        }
    }

    if (aliases_present > 1U)
    {
        LOGF("JSON Error: PacketsToConnection->settings contains ambiguous fake-DNS aliases; use exactly one of "
             "fake-dns, fake_dns, or mapdns");
        return false;
    }

    if (fake_dns == NULL)
    {
        return true;
    }

    const cJSON *fake_dns_object = NULL;
    bool         enabled         = true;

    if (cJSON_IsBool(fake_dns))
    {
        enabled = cJSON_IsTrue(fake_dns);
    }
    else if (cJSON_IsObject(fake_dns))
    {
        fake_dns_object      = fake_dns;
        uint32_t seen_fields = 0;
        cJSON_ArrayForEach(member, fake_dns_object)
        {
            const uint32_t field_bit = ptcFakeDnsFieldBit(member->string);
            if (field_bit == 0)
            {
                continue;
            }
            if ((seen_fields & field_bit) != 0)
            {
                LOGF("JSON Error: PacketsToConnection->settings->fake-dns contains duplicate field '%s'",
                     member->string);
                return false;
            }
            seen_fields |= field_bit;
        }
        if (! ptcFakeDnsLoadOptionalBoolean(
                fake_dns_object, "enabled", &enabled, "PacketsToConnection->settings->fake-dns->enabled"))
        {
            return false;
        }
    }
    else
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns must be a boolean or object");
        return false;
    }

    ip4_addr_t listen_addr;
    ip4_addr_t network;
    ip4_addr_t netmask;
    int64_t    port       = kPtcFakeDnsDefaultPort;
    int64_t    ttl        = kPtcFakeDnsDefaultTtl;
    int64_t    cache_size = kPtcFakeDnsDefaultRecords;

    if (! ptcFakeDnsLoadIpv4Setting(&listen_addr,
                                    fake_dns_object,
                                    "address",
                                    "198.18.0.2",
                                    "PacketsToConnection->settings->fake-dns->address") ||
        ! ptcFakeDnsLoadIpv4Setting(
            &network, fake_dns_object, "network", "100.64.0.0", "PacketsToConnection->settings->fake-dns->network") ||
        ! ptcFakeDnsLoadIpv4Setting(
            &netmask, fake_dns_object, "netmask", "255.192.0.0", "PacketsToConnection->settings->fake-dns->netmask"))
    {
        return false;
    }

    /*
     * ip4_output_if() substitutes the netif address for ANY. Multicast,
     * broadcast, and loopback are likewise not usable public reply identities
     * for this packet bridge. Reject them at configuration time instead of
     * publishing a listener whose wire source differs or is unroutable.
     */
    if (ip4_addr_isany_val(listen_addr) || ip4_addr_isloopback(&listen_addr) || ip4_addr_ismulticast(&listen_addr) ||
        ip4_addr_get_u32(&listen_addr) == IPADDR_BROADCAST)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->address must be a concrete non-loopback IPv4 "
             "unicast source");
        return false;
    }

    if (fake_dns_object != NULL &&
        (! ptcLoadOptionalInteger(
             fake_dns_object, "port", 1, UINT16_MAX, &port, "PacketsToConnection->settings->fake-dns->port") ||
         ! ptcLoadOptionalInteger(fake_dns_object,
                                  "ttl",
                                  0,
                                  (int64_t) kPtcFakeDnsMaxTtl,
                                  &ttl,
                                  "PacketsToConnection->settings->fake-dns->ttl") ||
         ! ptcLoadOptionalInteger(fake_dns_object,
                                  "cache-size",
                                  1,
                                  INT32_MAX,
                                  &cache_size,
                                  "PacketsToConnection->settings->fake-dns->cache-size")))
    {
        return false;
    }

    uint32_t netmask_host = lwip_ntohl(netmask.addr);
    uint32_t network_host = lwip_ntohl(network.addr) & netmask_host;
    uint32_t host_mask    = ~netmask_host;

    if ((host_mask & (host_mask + 1U)) != 0)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->netmask must be a contiguous IPv4 prefix mask");
        return false;
    }

    if (host_mask == 0 || (uint64_t) cache_size > (uint64_t) host_mask + 1U)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size does not fit in configured network");
        return false;
    }

    if (network_host == 0)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->network would reserve 0.0.0.0 as a fake address");
        return false;
    }

    const uint32_t listen_host = lwip_ntohl(listen_addr.addr);
    if ((listen_host & netmask_host) == network_host && (listen_host & host_mask) < (uint32_t) cache_size)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->address overlaps the allocated fake-IP record "
             "interval");
        return false;
    }

    ptc_fake_dns_geometry_t geometry;
    if (! ptcFakeDnsComputeGeometry((uint32_t) cache_size, &geometry))
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size exceeds safe allocation geometry "
             "(maximum %u records)",
             (unsigned int) kPtcFakeDnsMaxRecords);
        return false;
    }

    if (! enabled)
    {
        return true;
    }

    const isize_t           map_capacity = geometry.map_capacity;
    ptc_fake_dns_name_map_t names        = ptc_fake_dns_name_map_t_with_capacity(map_capacity);
    ptc_fake_dns_entry_t  **records      = memoryAllocateZero(geometry.record_bytes);

    if (UNLIKELY(ptc_fake_dns_name_map_t_capacity(&names) < (isize_t) map_capacity || records == NULL))
    {
        ptc_fake_dns_name_map_t_drop(&names);
        memoryFree(records);
        return false;
    }

    ptc_fake_dns_t *dns = &ts->fake_dns;
    dns->names          = names;
    dns->records        = records;
    dns->listen_addr    = listen_addr;
    dns->network_host   = network_host;
    dns->netmask_host   = netmask_host;
    dns->capacity       = (uint32_t) cache_size;
    dns->ttl            = (uint32_t) ttl;
    dns->listen_port    = (uint16_t) port;
    dns->enabled        = true;

    return true;
}

void ptcFakeDnsDestroy(ptc_tstate_t *ts)
{
    ptc_fake_dns_t *dns = &ts->fake_dns;

    if (dns->records == NULL)
    {
        return;
    }

    ptc_fake_dns_name_map_t_drop(&dns->names);

    ptc_fake_dns_entry_t *entry = dns->lru_head;
    while (entry != NULL)
    {
        ptc_fake_dns_entry_t *next = entry->next;

        if (entry->domain != NULL)
        {
            memoryFree(entry->domain);
        }
        memoryFree(entry);
        entry = next;
    }

    memoryFree(dns->records);
    memoryZero(dns, sizeof(*dns));
}

bool ptcFakeDnsOwnsDestination(tunnel_t *t, const ip4_addr_p_t *dest)
{
    const ptc_fake_dns_t *dns = &((ptc_tstate_t *) tunnelGetState(t))->fake_dns;

    return dns->enabled && dest->addr == dns->listen_addr.addr;
}

bool ptcFakeDnsShouldDropFragment(const ptc_fake_dns_t *dns, const ip4_addr_p_t *dest, uint8_t protocol,
                                  bool is_fragment)
{
    /* TCP shares the address but is ordinary routed traffic; only UDP belongs to fake DNS. */
    return is_fragment && protocol == IP_PROTO_UDP && dns->enabled && dest->addr == dns->listen_addr.addr;
}

ptc_fake_dns_result_t ptcFakeDnsHandleIpv4UdpPacket(tunnel_t *t, line_t *packet_line, sbuf_t *buf,
                                                    const struct ip_hdr *iphdr, const struct udp_hdr *udphdr)
{
    ptc_tstate_t   *ts  = tunnelGetState(t);
    ptc_fake_dns_t *dns = &ts->fake_dns;

    if (! dns->enabled || iphdr->dest.addr != dns->listen_addr.addr || lwip_ntohs(udphdr->dest) != dns->listen_port)
    {
        return (ptc_fake_dns_result_t) {0};
    }

    uint32_t ip_header_len = IPH_HL_BYTES(iphdr);
    uint32_t ip_total_len  = lwip_ntohs(IPH_LEN(iphdr));
    uint32_t udp_len       = lwip_ntohs(udphdr->len);

    if (udp_len < UDP_HLEN || ip_header_len + udp_len != ip_total_len || inet_chksum(iphdr, (u16_t) ip_header_len) != 0)
    {
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    if (udphdr->chksum != 0)
    {
        struct pbuf udp_packet = {
            .next    = NULL,
            .payload = (void *) udphdr,
            .tot_len = (u16_t) udp_len,
            .len     = (u16_t) udp_len,
            .ref     = 1,
        };
        const ip4_addr_t source      = {.addr = iphdr->src.addr};
        const ip4_addr_t destination = {.addr = iphdr->dest.addr};

        if (inet_chksum_pseudo(&udp_packet, IP_PROTO_UDP, (u16_t) udp_len, &source, &destination) != 0)
        {
            lineReuseBuffer(packet_line, buf);
            return (ptc_fake_dns_result_t) {.handled = true};
        }
    }

    const uint8_t *dns_query     = ((const uint8_t *) udphdr) + UDP_HLEN;
    uint32_t       dns_query_len = udp_len - UDP_HLEN;
    uint32_t       max_dns_len   = dns_query_len + ((uint32_t) kPtcDnsMaxQuestions * kPtcDnsAnswerALen);

    if (max_dns_len > UINT16_MAX - UDP_HLEN)
    {
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    buffer_pool_t *pool       = lineGetBufferPool(packet_line);
    uint32_t       packet_cap = UDP_HLEN + max_dns_len;
    sbuf_t        *response   = bufferpoolGetBestFit(pool, packet_cap, bufferpoolGetLargeBufferPadding(pool));
    if (UNLIKELY(response == NULL))
    {
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }
    uint8_t        *packet = sbufGetMutablePtr(response);
    struct udp_hdr *rudp   = (struct udp_hdr *) packet;
    uint8_t        *rdns   = packet + UDP_HLEN;

    int dns_response_len = ptcFakeDnsBuildResponse(ts, dns_query, dns_query_len, rdns, max_dns_len);
    if (dns_response_len < 0)
    {
        bufferpoolReuseBuffer(pool, response);
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    uint32_t response_len = UDP_HLEN + (uint32_t) dns_response_len;
    sbufSetLength(response, response_len);
    memoryZero(packet, UDP_HLEN);

    rudp->src  = udphdr->dest;
    rudp->dest = udphdr->src;
    rudp->len  = lwip_htons((uint16_t) (UDP_HLEN + (uint32_t) dns_response_len));

    const ip4_addr_t source      = {.addr = iphdr->dest.addr};
    const ip4_addr_t destination = {.addr = iphdr->src.addr};
    struct pbuf      udp_packet  = {
              .next    = NULL,
              .payload = packet,
              .tot_len = (u16_t) response_len,
              .len     = (u16_t) response_len,
              .ref     = 1,
    };
    rudp->chksum = inet_chksum_pseudo(&udp_packet, IP_PROTO_UDP, (u16_t) response_len, &source, &destination);
    if (rudp->chksum == 0)
    {
        rudp->chksum = 0xFFFF;
    }

    lineReuseBuffer(packet_line, buf);
    return (ptc_fake_dns_result_t) {
        .response    = response,
        .source      = source,
        .destination = destination,
        .handled     = true,
    };
}

/*
 * Publishes one fake-DNS reply through the worker netif's MTU-aware IPv4 path.
 *
 * The reply reaches this function as one UDP datagram, and a maximum-size
 * multi-question answer is around 776 bytes - larger than small legal IPv4
 * MTUs this node supports. Emitting it straight at the packet neighbour
 * handed the packet topology one oversized frame it had no way to carry, on a
 * path the node's own documentation described as fragmenting.
 *
 * Going through ip4_output_if() makes lwIP construct the IPv4 header, allocate
 * the identification value, and apply MTU fragmentation. It is safe
 * under the core lock because the netif output callback only queues detached
 * packet messages; it never calls the neighbour chain inline.
 *
 * Consumes `response` on every path. The PBUF_REF is synchronous through the
 * complete IPv4 output loop; once it returns, every queued output owns a detached
 * copy and the source buffer has exactly one place to be recycled.
 */
bool ptcFakeDnsPublishResponseLocked(tunnel_t *t, line_t *packet_line, sbuf_t *response, const ip4_addr_t *source,
                                     const ip4_addr_t *destination)
{
    buffer_pool_t             *pool      = lineGetBufferPool(packet_line);
    interface_route_context_t *route_ctx = ptcFindOrCreateRouteContextV4(t, lineGetWID(packet_line), NULL);

    if (UNLIKELY(route_ctx == NULL))
    {
        bufferpoolReuseBuffer(pool, response);
        return false;
    }

    const uint32_t response_len = sbufGetLength(response);
    struct pbuf   *p            = pbuf_alloc(PBUF_IP, (u16_t) response_len, PBUF_RAM);

    if (UNLIKELY(p == NULL || pbuf_take(p, sbufGetRawPtr(response), (u16_t) response_len) != ERR_OK))
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        bufferpoolReuseBuffer(pool, response);
        return false;
    }

    struct netif *netif  = &route_ctx->netif;
    const err_t   result = ip4_output_if(p, source, destination, UDP_TTL, 0, IP_PROTO_UDP, netif);

    pbuf_free(p);
    bufferpoolReuseBuffer(pool, response);
    return result == ERR_OK;
}

bool ptcFakeDnsApplyMappedDestination(tunnel_t *t, address_context_t *dest_ctx, const ip_addr_t *ip, uint16_t port,
                                      uint8_t protocol)
{
    if (! ipAddrIsV4(ip))
    {
        return false;
    }

    ptc_tstate_t         *ts    = tunnelGetState(t);
    ptc_fake_dns_entry_t *entry = ptcFakeDnsLookupByIp(&ts->fake_dns, &ip->u_addr.ip4);

    if (entry == NULL)
    {
        return false;
    }

    addresscontextDomainSet(dest_ctx, entry->domain, entry->domain_len);
    addresscontextSetPort(dest_ctx, port);
    addresscontextSetOnlyProtocol(dest_ctx, protocol);
    addresscontextSetDomainStrategy(dest_ctx, kDsPreferIpV4);
    return true;
}
