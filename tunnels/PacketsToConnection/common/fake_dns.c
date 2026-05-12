#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPtcDnsHeaderLen          = 12,
    kPtcDnsMaxQuestions       = 32,
    kPtcDnsAnswerALen         = 16,
    kPtcDnsTypeA              = 1,
    kPtcDnsClassIn            = 1,
    kPtcFakeDnsDefaultPort    = 53,
    kPtcFakeDnsDefaultTtl     = 1,
    kPtcFakeDnsDefaultRecords = 10000
};

typedef struct ptc_dns_answer_s
{
    uint32_t fake_addr_network;
    uint16_t name_offset;
} ptc_dns_answer_t;

static sbuf_t *ptcFakeDnsAllocateBuffer(buffer_pool_t *pool, uint32_t len)
{
    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
}

static char *ptcFakeDnsDuplicateString(const char *value)
{
    size_t len = stringLength(value);
    char  *out = memoryAllocate(len + 1U);

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

static char ptcDnsAsciiLower(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (char) (c + ('a' - 'A'));
    }
    return c;
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
            domain[out++] = ptcDnsAsciiLower((char) packet[pos + i]);
        }
        pos += label_len;
    }

    if (out == 0 || out > UINT8_MAX)
    {
        return false;
    }

    domain[out]  = '\0';
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

static void ptcFakeDnsClearEntryName(ptc_fake_dns_t *dns, ptc_fake_dns_entry_t *entry)
{
    if (entry->domain == NULL)
    {
        return;
    }

    ptc_fake_dns_name_key_t key = {.name = entry->domain, .len = entry->domain_len};
    (void) ptc_fake_dns_name_map_t_erase(&dns->names, key);
    memoryFree(entry->domain);
    entry->domain     = NULL;
    entry->domain_len = 0;
}

static ptc_fake_dns_entry_t *ptcFakeDnsFindByName(ptc_fake_dns_t *dns, const char *domain, uint8_t domain_len)
{
    ptc_fake_dns_name_key_t  key = {.name = domain, .len = domain_len};
    ptc_fake_dns_name_map_t_iter it  = ptc_fake_dns_name_map_t_find(&dns->names, key);

    if (it.ref == ptc_fake_dns_name_map_t_end(&dns->names).ref)
    {
        return NULL;
    }

    return it.ref->second;
}

static uint32_t ptcFakeDnsGetOrCreate(ptc_fake_dns_t *dns, const char *domain, uint8_t domain_len)
{
    ptc_fake_dns_entry_t *entry = ptcFakeDnsFindByName(dns, domain, domain_len);

    if (entry != NULL)
    {
        ptcFakeDnsTouch(dns, entry);
        return entry->fake_addr_network;
    }

    if (dns->capacity == 0)
    {
        return 0;
    }

    if (dns->used < dns->capacity)
    {
        entry        = memoryAllocateZero(sizeof(*entry));
        entry->index = dns->used++;
    }
    else
    {
        entry = dns->lru_head;
        assert(entry != NULL);
        ptcFakeDnsLruUnlink(dns, entry);
        ptcFakeDnsClearEntryName(dns, entry);
    }

    entry->domain = memoryAllocate((size_t) domain_len + 1U);
    memoryCopy(entry->domain, domain, domain_len);
    entry->domain[domain_len] = '\0';
    entry->domain_len         = domain_len;

    uint32_t fake_host       = dns->network_host | entry->index;
    entry->fake_addr_network = lwip_htonl(fake_host);
    dns->records[entry->index] = entry;

    ptcFakeDnsLruPushTail(dns, entry);

    ptc_fake_dns_name_key_t key = {.name = entry->domain, .len = entry->domain_len};
    (void) ptc_fake_dns_name_map_t_insert(&dns->names, key, entry);
    return entry->fake_addr_network;
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

static int ptcFakeDnsBuildResponse(ptc_tstate_t *ts, const uint8_t *query, uint32_t query_len, uint8_t *response,
                                   uint32_t response_capacity)
{
    ptc_dns_answer_t answers[kPtcDnsMaxQuestions];
    uint16_t         question_count;
    uint16_t         answer_count = 0;
    uint32_t         offset       = kPtcDnsHeaderLen;
    char             domain[256];

    if (query_len < kPtcDnsHeaderLen)
    {
        return -1;
    }

    uint16_t query_flags = ptcDnsRead16(query + 2);
    if ((query_flags & 0x8000U) != 0)
    {
        return -1;
    }

    question_count = ptcDnsRead16(query + 4);
    if (question_count == 0 || question_count > kPtcDnsMaxQuestions)
    {
        return -1;
    }

    for (uint16_t i = 0; i < question_count; ++i)
    {
        uint32_t name_offset = offset;
        uint8_t  domain_len  = 0;

        if (name_offset > 0x3FFFU || ! ptcDnsReadQuestionName(query, query_len, &offset, domain, &domain_len))
        {
            return -1;
        }

        if (offset + 4U > query_len)
        {
            return -1;
        }

        uint16_t qtype  = ptcDnsRead16(query + offset);
        uint16_t qclass = ptcDnsRead16(query + offset + 2U);
        offset += 4U;

        if (qtype == kPtcDnsTypeA && qclass == kPtcDnsClassIn)
        {
            uint32_t fake_addr = ptcFakeDnsGetOrCreate(&ts->fake_dns, domain, domain_len);
            if (fake_addr != 0 && answer_count < kPtcDnsMaxQuestions)
            {
                answers[answer_count++] =
                    (ptc_dns_answer_t) {.fake_addr_network = fake_addr, .name_offset = (uint16_t) name_offset};
            }
        }
    }

    uint32_t dns_len = offset + ((uint32_t) answer_count * kPtcDnsAnswerALen);
    if (dns_len > response_capacity)
    {
        return -1;
    }

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

    return (int) dns_len;
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

static bool ptcFakeDnsLoadIpv4Setting(ip4_addr_t *out, const cJSON *settings, const char *key, const char *def,
                                      const char *json_path)
{
    char *value = NULL;
    bool  ok;

    if (settings != NULL)
    {
        getStringFromJsonObjectOrDefault(&value, settings, key, def);
    }
    else
    {
        value = ptcFakeDnsDuplicateString(def);
    }

    ok = ptcFakeDnsParseIpv4(out, value, json_path);
    memoryFree(value);
    return ok;
}

bool ptcFakeDnsLoadSettings(ptc_tstate_t *ts, const cJSON *settings)
{
    if (settings == NULL)
    {
        return true;
    }

    const cJSON *fake_dns = cJSON_GetObjectItemCaseSensitive(settings, "fake-dns");
    if (fake_dns == NULL)
    {
        fake_dns = cJSON_GetObjectItemCaseSensitive(settings, "fake_dns");
    }
    if (fake_dns == NULL)
    {
        fake_dns = cJSON_GetObjectItemCaseSensitive(settings, "mapdns");
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
        fake_dns_object = fake_dns;
        getBoolFromJsonObjectOrDefault(&enabled, fake_dns_object, "enabled", true);
    }
    else
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns must be a boolean or object");
        return false;
    }

    if (! enabled)
    {
        return true;
    }

    ip4_addr_t listen_addr;
    ip4_addr_t network;
    ip4_addr_t netmask;
    int        port       = kPtcFakeDnsDefaultPort;
    int        ttl        = kPtcFakeDnsDefaultTtl;
    int        cache_size = kPtcFakeDnsDefaultRecords;

    if (! ptcFakeDnsLoadIpv4Setting(&listen_addr, fake_dns_object, "address", "198.18.0.2",
                                    "PacketsToConnection->settings->fake-dns->address") ||
        ! ptcFakeDnsLoadIpv4Setting(&network, fake_dns_object, "network", "100.64.0.0",
                                    "PacketsToConnection->settings->fake-dns->network") ||
        ! ptcFakeDnsLoadIpv4Setting(&netmask, fake_dns_object, "netmask", "255.192.0.0",
                                    "PacketsToConnection->settings->fake-dns->netmask"))
    {
        return false;
    }

    if (fake_dns_object != NULL)
    {
        getIntFromJsonObjectOrDefault(&port, fake_dns_object, "port", kPtcFakeDnsDefaultPort);
        getIntFromJsonObjectOrDefault(&ttl, fake_dns_object, "ttl", kPtcFakeDnsDefaultTtl);
        getIntFromJsonObjectOrDefault(&cache_size, fake_dns_object, "cache-size", kPtcFakeDnsDefaultRecords);
    }

    if (port < 1 || port > UINT16_MAX)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->port must be in range [1, 65535]");
        return false;
    }

    if (ttl < 0)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->ttl must be zero or greater");
        return false;
    }

    if (cache_size < 1)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size must be at least 1");
        return false;
    }

    uint32_t netmask_host = lwip_ntohl(netmask.addr);
    uint32_t network_host = lwip_ntohl(network.addr) & netmask_host;
    uint32_t host_mask    = ~netmask_host;

    if (host_mask == 0 || (uint32_t) cache_size > host_mask)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size does not fit in configured network");
        return false;
    }

    ptc_fake_dns_t *dns = &ts->fake_dns;
    dns->names          = ptc_fake_dns_name_map_t_with_capacity((uint32_t) cache_size);
    dns->records        = memoryAllocateZero(sizeof(*dns->records) * (uint32_t) cache_size);
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
    memorySet(dns, 0, sizeof(*dns));
}

bool ptcFakeDnsHandleIpv4UdpPacket(tunnel_t *t, line_t *packet_line, sbuf_t *buf, const struct ip_hdr *iphdr,
                                   const struct udp_hdr *udphdr)
{
    ptc_tstate_t *ts  = tunnelGetState(t);
    ptc_fake_dns_t *dns = &ts->fake_dns;

    if (! dns->enabled || iphdr->dest.addr != dns->listen_addr.addr ||
        lwip_ntohs(udphdr->dest) != dns->listen_port)
    {
        return false;
    }

    uint32_t ip_header_len = IPH_HL_BYTES(iphdr);
    uint32_t ip_total_len  = lwip_ntohs(IPH_LEN(iphdr));
    uint32_t udp_len       = lwip_ntohs(udphdr->len);

    if (udp_len < UDP_HLEN || ip_header_len + udp_len > ip_total_len)
    {
        lineReuseBuffer(packet_line, buf);
        return true;
    }

    const uint8_t *dns_query     = ((const uint8_t *) udphdr) + UDP_HLEN;
    uint32_t       dns_query_len = udp_len - UDP_HLEN;
    uint32_t       max_dns_len   = dns_query_len + ((uint32_t) kPtcDnsMaxQuestions * kPtcDnsAnswerALen);

    if (max_dns_len > UINT16_MAX - IP_HLEN - UDP_HLEN)
    {
        lineReuseBuffer(packet_line, buf);
        return true;
    }

    buffer_pool_t *pool       = lineGetBufferPool(packet_line);
    uint32_t       packet_cap = IP_HLEN + UDP_HLEN + max_dns_len;
    sbuf_t        *response   = ptcFakeDnsAllocateBuffer(pool, packet_cap);
    uint8_t       *packet     = sbufGetMutablePtr(response);
    struct ip_hdr *rip        = (struct ip_hdr *) packet;
    struct udp_hdr *rudp      = (struct udp_hdr *) (packet + IP_HLEN);
    uint8_t       *rdns       = packet + IP_HLEN + UDP_HLEN;

    int dns_response_len = ptcFakeDnsBuildResponse(ts, dns_query, dns_query_len, rdns, max_dns_len);
    if (dns_response_len < 0)
    {
        bufferpoolReuseBuffer(pool, response);
        lineReuseBuffer(packet_line, buf);
        return true;
    }

    uint32_t response_len = IP_HLEN + UDP_HLEN + (uint32_t) dns_response_len;
    sbufSetLength(response, response_len);
    memorySet(packet, 0, IP_HLEN + UDP_HLEN);

    IPH_VHL_SET(rip, 4, IP_HLEN / 4U);
    IPH_TOS_SET(rip, 0);
    IPH_LEN_SET(rip, lwip_htons((uint16_t) response_len));
    IPH_ID_SET(rip, lwip_htons((uint16_t) ++ts->ipv4_identification));
    IPH_OFFSET_SET(rip, 0);
    IPH_TTL_SET(rip, UDP_TTL);
    IPH_PROTO_SET(rip, IP_PROTO_UDP);
    IPH_CHKSUM_SET(rip, 0);
    rip->src.addr  = iphdr->dest.addr;
    rip->dest.addr = iphdr->src.addr;

    rudp->src  = udphdr->dest;
    rudp->dest = udphdr->src;
    rudp->len  = lwip_htons((uint16_t) (UDP_HLEN + (uint32_t) dns_response_len));

    calcFullPacketChecksum(packet);

#ifdef DEBUG
    lineLock(packet_line);
#endif

    tunnelPrevDownStreamPayload(t, packet_line, response);

#ifdef DEBUG
    if (! lineIsAlive(packet_line))
    {
        LOGF("PacketsToConnection: packet line died while sending fake DNS response");
        terminateProgram(1);
    }
    lineUnlock(packet_line);
#endif

    lineReuseBuffer(packet_line, buf);
    return true;
}

bool ptcFakeDnsApplyMappedDestination(tunnel_t *t, address_context_t *dest_ctx, const ip_addr_t *ip, uint16_t port,
                                      uint8_t protocol)
{
    if (! ipAddrIsV4(ip))
    {
        return false;
    }

    ptc_tstate_t          *ts    = tunnelGetState(t);
    ptc_fake_dns_entry_t  *entry = ptcFakeDnsLookupByIp(&ts->fake_dns, &ip->u_addr.ip4);

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
