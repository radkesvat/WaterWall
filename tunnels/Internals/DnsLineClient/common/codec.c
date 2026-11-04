#include "DnsLineClient/internal.h"

/*
 * Wire format handling is delegated entirely to the c-ares record API
 * (ares_dns_record_create/query_add/write and ares_dns_parse). This file only
 * validates the parsed record against the outstanding question and converts
 * the A/AAAA answers into dns_resolved_addr_t entries shaped exactly like the
 * worker c-ares path produces them (port 0, family, addrlen, ttl).
 */

bool dnslineclientNormalizeDomain(const char *domain, char *out)
{
    if (domain == NULL)
    {
        return false;
    }

    size_t len = stringLength(domain);
    if (len > 0 && domain[len - 1] == '.')
    {
        --len;
    }
    if (len == 0 || len > kDnsLineClientMaxDomainLength)
    {
        return false;
    }

    size_t label = 0;
    for (size_t i = 0; i < len; ++i)
    {
        char c = domain[i];
        if (c == '.')
        {
            if (label == 0)
            {
                return false;
            }
            label = 0;
        }
        else
        {
            // Hostname bytes only: a presentation escape such as "\065" would go on the wire changed.
            const bool hostname_byte = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                       c == '-' || c == '_';
            if (++label > kDnsLineClientMaxLabelLength || ! hostname_byte)
            {
                return false;
            }
        }
        out[i] = (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
    }
    out[len] = '\0';

    if (label == 0)
    {
        return false;
    }

    struct in6_addr probe;
    if (inet_pton(AF_INET, out, &probe) == 1 || inet_pton(AF_INET6, out, &probe) == 1)
    {
        return false;
    }
    return true;
}

int dnslineclientCodecBuildQuery(const char *domain, uint16_t id, ares_dns_rec_type_t qtype, unsigned char **out,
                                 size_t *out_len)
{
    ares_dns_record_t *rec = NULL;

    *out     = NULL;
    *out_len = 0;

    ares_status_t rc = ares_dns_record_create(&rec, id, ARES_FLAG_RD, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (rc != ARES_SUCCESS)
    {
        return (int) rc;
    }

    rc = ares_dns_record_query_add(rec, domain, qtype, ARES_CLASS_IN);
    if (rc == ARES_SUCCESS)
    {
        rc = ares_dns_write(rec, out, out_len);
    }
    ares_dns_record_destroy(rec);

    if (rc != ARES_SUCCESS)
    {
        *out     = NULL;
        *out_len = 0;
    }
    return (int) rc;
}

static int dnslineclientStatusFromRcode(ares_dns_rcode_t rcode)
{
    switch (rcode)
    {
    case ARES_RCODE_NOERROR:
        return ARES_SUCCESS;
    case ARES_RCODE_FORMERR:
        return ARES_EFORMERR;
    case ARES_RCODE_SERVFAIL:
        return ARES_ESERVFAIL;
    case ARES_RCODE_NXDOMAIN:
        return ARES_ENOTFOUND;
    case ARES_RCODE_NOTIMP:
        return ARES_ENOTIMP;
    case ARES_RCODE_REFUSED:
        return ARES_EREFUSED;
    default:
        return ARES_EBADRESP;
    }
}

static bool dnslineclientNameInChain(const char *name, const char *const *chain, uint32_t chain_len)
{
    for (uint32_t i = 0; i < chain_len; ++i)
    {
        if (stricmp(name, chain[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

/* Follow CNAME records inside this message only, starting at the question name. */
static uint32_t dnslineclientCollectCnameChain(const ares_dns_record_t *rec, const char *domain,
                                               const char *chain[kDnsLineClientMaxCnameHops + 1], uint32_t *min_ttl)
{
    const size_t answers   = ares_dns_record_rr_cnt(rec, ARES_SECTION_ANSWER);
    uint32_t     chain_len = 1;

    chain[0] = domain;
    while (chain_len <= kDnsLineClientMaxCnameHops)
    {
        const char *current = chain[chain_len - 1];
        const char *target  = NULL;
        uint32_t    ttl     = 0;

        for (size_t i = 0; i < answers; ++i)
        {
            const ares_dns_rr_t *rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, i);
            if (rr == NULL || ares_dns_rr_get_type(rr) != ARES_REC_TYPE_CNAME ||
                ares_dns_rr_get_class(rr) != ARES_CLASS_IN || stricmp(ares_dns_rr_get_name(rr), current) != 0)
            {
                continue;
            }
            target = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME);
            ttl    = ares_dns_rr_get_ttl(rr);
            break;
        }

        if (target == NULL || target[0] == '\0' || dnslineclientNameInChain(target, chain, chain_len))
        {
            break; // end of chain, or a loop
        }
        chain[chain_len++] = target;
        if (ttl < *min_ttl)
        {
            *min_ttl = ttl;
        }
    }
    return chain_len;
}

static bool dnslineclientQuestionMatches(const ares_dns_record_t *rec, const char *domain, ares_dns_rec_type_t qtype)
{
    if (ares_dns_record_query_cnt(rec) != 1)
    {
        return false;
    }

    const char         *qname  = NULL;
    ares_dns_rec_type_t rtype  = 0;
    ares_dns_class_t    qclass = 0;
    if (ares_dns_record_query_get(rec, 0, &qname, &rtype, &qclass) != ARES_SUCCESS || qname == NULL)
    {
        return false;
    }

    size_t qlen = stringLength(qname);
    if (qlen > 0 && qname[qlen - 1] == '.')
    {
        --qlen;
    }
    return rtype == qtype && qclass == ARES_CLASS_IN && qlen == stringLength(domain) &&
           strnicmp(qname, domain, qlen) == 0;
}

static void dnslineclientExtractAddresses(const ares_dns_record_t *rec, const char *domain, ares_dns_rec_type_t qtype,
                                          uint32_t min_ttl, uint32_t max_ttl, dnslineclient_answer_t *out)
{
    const char *chain[kDnsLineClientMaxCnameHops + 1];
    uint32_t    ttl       = UINT32_MAX;
    uint32_t    chain_len = dnslineclientCollectCnameChain(rec, domain, chain, &ttl);

    const size_t answers = ares_dns_record_rr_cnt(rec, ARES_SECTION_ANSWER);
    size_t       count   = 0;
    for (size_t i = 0; i < answers; ++i)
    {
        const ares_dns_rr_t *rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, i);
        if (rr != NULL && ares_dns_rr_get_type(rr) == qtype && ares_dns_rr_get_class(rr) == ARES_CLASS_IN &&
            dnslineclientNameInChain(ares_dns_rr_get_name(rr), chain, chain_len))
        {
            ++count;
        }
    }
    if (count > kDnsLineClientMaxAddrsPerType)
    {
        count = kDnsLineClientMaxAddrsPerType;
    }
    if (count == 0)
    {
        out->status = ARES_ENODATA;
        return;
    }

    out->addrs  = memoryAllocate(count * sizeof(dns_resolved_addr_t));
    size_t used = 0;
    for (size_t i = 0; i < answers && used < count; ++i)
    {
        const ares_dns_rr_t *rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, i);
        if (rr == NULL || ares_dns_rr_get_type(rr) != qtype || ares_dns_rr_get_class(rr) != ARES_CLASS_IN ||
            ! dnslineclientNameInChain(ares_dns_rr_get_name(rr), chain, chain_len))
        {
            continue;
        }

        dns_resolved_addr_t *entry = &out->addrs[used];
        memoryZero(entry, sizeof(*entry));
        if (qtype == ARES_REC_TYPE_A)
        {
            const struct in_addr *a = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
            if (a == NULL)
            {
                continue;
            }
            struct sockaddr_in *sin = (struct sockaddr_in *) &entry->addr;
            sin->sin_family         = AF_INET;
            sin->sin_port           = 0;
            memoryCopy(&sin->sin_addr, a, sizeof(sin->sin_addr));
            entry->addrlen = (socklen_t) sizeof(struct sockaddr_in);
            entry->family  = AF_INET;
        }
        else
        {
            const struct ares_in6_addr *a6 = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR);
            if (a6 == NULL)
            {
                continue;
            }
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &entry->addr;
            sin6->sin6_family         = AF_INET6;
            sin6->sin6_port           = 0;
            memoryCopy(&sin6->sin6_addr, a6->_S6_un._S6_u8, sizeof(sin6->sin6_addr));
            entry->addrlen = (socklen_t) sizeof(struct sockaddr_in6);
            entry->family  = AF_INET6;
        }

        uint32_t rr_ttl = ares_dns_rr_get_ttl(rr);
        if (rr_ttl < ttl)
        {
            ttl = rr_ttl;
        }
        ++used;
    }

    if (used == 0)
    {
        memoryFree(out->addrs);
        out->addrs  = NULL;
        out->status = ARES_ENODATA;
        return;
    }

    if (ttl < min_ttl)
    {
        ttl = min_ttl;
    }
    if (ttl > max_ttl)
    {
        ttl = max_ttl;
    }
    for (size_t i = 0; i < used; ++i)
    {
        out->addrs[i].ttl = (int) min(ttl, (uint32_t) INT32_MAX);
    }
    out->naddrs = used;
    out->ttl    = ttl;
    out->status = ARES_SUCCESS;
}

dnslineclient_parse_result_e dnslineclientCodecParseResponse(const unsigned char *buf, size_t len, const char *domain,
                                                             const uint16_t *ids, const ares_dns_rec_type_t *qtypes,
                                                             uint32_t nslots, uint32_t min_ttl, uint32_t max_ttl,
                                                             dnslineclient_answer_t *out)
{
    memoryZero(out, sizeof(*out));

    // A DNS header is 12 bytes; anything shorter cannot carry an id worth trusting.
    if (buf == NULL || len < 12 || len > kDnsLineClientMaxResponseBytes)
    {
        return kDnsLineClientParseIgnored;
    }

    ares_dns_record_t *rec = NULL;
    if (ares_dns_parse(buf, len, 0, &rec) != ARES_SUCCESS)
    {
        /*
         * Undecodable bytes that still carry one of our ids and the response
         * bit are a broken answer from the server; anything else is noise.
         * Only the two id bytes and the QR bit of the fixed header are read.
         */
        uint16_t raw_id = (uint16_t) (((uint16_t) buf[0] << 8U) | buf[1]);
        bool     qr     = (buf[2] & 0x80U) != 0;
        for (uint32_t i = 0; qr && i < nslots; ++i)
        {
            if (ids[i] == raw_id)
            {
                out->slot   = i;
                out->status = ARES_EBADRESP;
                return kDnsLineClientParseAnswered;
            }
        }
        return kDnsLineClientParseIgnored;
    }

    dnslineclient_parse_result_e result = kDnsLineClientParseIgnored;
    const uint16_t               id     = ares_dns_record_get_id(rec);
    const unsigned short         flags  = ares_dns_record_get_flags(rec);
    const ares_dns_rcode_t       rcode  = ares_dns_record_get_rcode(rec);
    uint32_t                     slot   = nslots;

    for (uint32_t i = 0; i < nslots; ++i)
    {
        if (ids[i] == id)
        {
            slot = i;
            break;
        }
    }

    if (slot == nslots || (flags & ARES_FLAG_QR) == 0)
    {
        goto done; // stray or spoofed; keep waiting for the real answer
    }

    /*
     * Servers may answer FORMERR/REFUSED/NOTIMP without echoing the question.
     * An id-matched error with no question ends the try instead of waiting
     * for the timer and counts as a failed try. NXDOMAIN still needs the
     * question, because it ends the whole lookup.
     */
    if (ares_dns_record_query_cnt(rec) == 0 && rcode != ARES_RCODE_NOERROR && rcode != ARES_RCODE_NXDOMAIN)
    {
        result      = kDnsLineClientParseAnswered;
        out->slot   = slot;
        out->status = dnslineclientStatusFromRcode(rcode);
        goto done;
    }

    if (! dnslineclientQuestionMatches(rec, domain, qtypes[slot]))
    {
        goto done;
    }

    result    = kDnsLineClientParseAnswered;
    out->slot = slot;

    if (ares_dns_record_get_opcode(rec) != ARES_OPCODE_QUERY || (flags & ARES_FLAG_TC) != 0)
    {
        // Truncated answers would need a TCP retry, which this client does not implement.
        out->status = ARES_EBADRESP;
        goto done;
    }

    out->status = dnslineclientStatusFromRcode(rcode);
    if (out->status == ARES_SUCCESS)
    {
        dnslineclientExtractAddresses(rec, domain, qtypes[slot], min_ttl, max_ttl, out);
    }

done:
    ares_dns_record_destroy(rec);
    return result;
}
