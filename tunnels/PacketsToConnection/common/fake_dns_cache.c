#include "fake_dns_internal.h"

#include "loggers/dns_logger.h"

static char *ptcFakeDnsDuplicateString(const char *value, uint8_t len)
{
    char *out = memoryAllocate((size_t) len + 1U);

    memoryCopy(out, value, len);
    out[len] = '\0';
    return out;
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

static void ptcFakeDnsDiscardStagedMappings(ptc_dns_mapping_t *mappings, uint8_t mapping_count)
{
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        ptc_dns_mapping_t *mapping = &mappings[i];

        if (! mapping->staged)
        {
            continue;
        }
        assert(mapping->entry != NULL);
        memoryFree(mapping->entry->domain);
        memoryFree(mapping->entry);
        mapping->entry = NULL;
    }
}

/*
 * Resolve every A/IN question as one cache transaction.
 *
 * No existing key, record, or LRU link is changed until every new entry and
 * domain has been allocated and every new key is resident in the pre-reserved
 * map. Heap allocation is fatal on failure, and unique staged keys fit the
 * reserved capacity. Existing entries used by this response are pinned while
 * victims are selected, so every emitted fake address remains reverse-resolvable
 * after the whole reply is committed.
 */
bool ptcFakeDnsCommitQuestions(ptc_fake_dns_t *dns, ptc_dns_question_t *questions, int question_count,
                               ptc_dns_mapping_t *mappings, uint8_t *mapping_count_out, uint64_t now_ms)
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

        char *domain               = ptcFakeDnsDuplicateString(mapping->domain, mapping->domain_len);
        mapping->entry             = memoryAllocateZero(sizeof(*mapping->entry));
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
            while (victim != NULL &&
                   (victim->lease_until_ms > now_ms || ptcFakeDnsEntryIsPinned(mappings, mapping_count, victim)))
            {
                victim = victim->next;
            }
            if (UNLIKELY(victim == NULL))
            {
                ptcFakeDnsDiscardStagedMappings(mappings, mapping_count);
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
        // Deduplication and lookup ran under the same lock; this key is new.
        const bool inserted = ptc_fake_dns_name_map_t_insert(&dns->names, key, mapping->entry).inserted;
        assert(inserted);
        discard inserted;
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
    }

    /* Apply successful lookup touches only after the transaction cannot fail. */
    for (uint8_t i = 0; i < mapping_count; ++i)
    {
        const uint64_t ttl_ms             = (uint64_t) dns->ttl * 1000U;
        mappings[i].entry->lease_until_ms = now_ms > UINT64_MAX - ttl_ms ? UINT64_MAX : now_ms + ttl_ms;
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

bool ptcFakeDnsApplyMappedDestination(tunnel_t *t, address_context_t *dest_ctx, const ip_addr_t *ip, uint16_t port,
                                      uint8_t protocol)
{
    if (! ipAddrIsV4(ip))
    {
        return false;
    }

    ptc_tstate_t *ts = tunnelGetState(t);
    char          domain[256];
    uint8_t       length = 0;
    mutexLock(&ts->dns_lock);
    ptc_fake_dns_entry_t *entry = ptcFakeDnsLookupByIp(&ts->fake_dns, &ip->u_addr.ip4);
    if (entry != NULL)
    {
        length = entry->domain_len;
        memoryCopy(domain, entry->domain, length);
    }
    mutexUnlock(&ts->dns_lock);
    if (length == 0)
        return false;

    addresscontextDomainSet(dest_ctx, domain, length);
    addresscontextSetPort(dest_ctx, port);
    addresscontextSetOnlyProtocol(dest_ctx, protocol);
    addresscontextSetDomainStrategy(dest_ctx, kDsPreferIpV4);
    return true;
}
