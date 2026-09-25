#include "structure.h"

sbuf_t *hpcBuffer(line_t *l, size_t n)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *b    = bufferpoolTryGetBestFit(pool, n, bufferpoolGetLargeBufferPadding(pool));
    if (b && sbufGetMaximumWriteableSize(b) < n)
    {
        lineReuseBuffer(l, b);
        return NULL;
    }
    return b;
}
static bool append(char *out, size_t cap, size_t *at, const char *s)
{
    size_t n = stringLength(s);
    if (n > cap - *at)
        return false;
    memoryCopy(out + *at, s, n);
    *at += n;
    out[*at] = 0;
    return true;
}
/* Copy the authority before any address-context setter can release its domain. */
static bool selectAuthority(const hpc_tstate_t *ts, line_t *l, bool prepared, hps_authority_t *authority)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);
    if (dest->proto_udp || dest->proto_icmp || dest->proto_packet)
        return false;
    uint16_t port = prepared || ts->dynamic_port ? dest->port : ts->port;
    if (! port)
        return false;
    char        host[256];
    const char *target = ts->target;
    if (prepared || ts->dynamic_address)
    {
        if (addresscontextIsDomain(dest) && ! (ts->resolve_domains && addresscontextIsDomainResolved(dest)))
        {
            if (! dest->domain || ! dest->domain_len || stringLength(dest->domain) != dest->domain_len)
                return false;
            memoryCopy(host, dest->domain, dest->domain_len);
            host[dest->domain_len] = 0;
        }
        else if (addresscontextIsIpType(dest) || (ts->resolve_domains && addresscontextIsDomainResolved(dest)))
        {
            if (! ipaddr_ntoa_r(&dest->ip_address, host, sizeof(host)))
                return false;
        }
        else
            return false;
        target = host;
    }
    char wire[272];
    bool bracket = stringChr(target, ':') && target[0] != '[';
    int  n       = stringNPrintf(wire, sizeof(wire), bracket ? "[%s]:%u" : "%s:%u", target, (unsigned) port);
    if (n < 0 || (size_t) n >= sizeof(wire) || ! hpsAuthority(wire, (size_t) n, true, authority))
        return false;
    return true;
}

bool hpcDomainResolverPrepare(tunnel_t *resolver, tunnel_t *owner, line_t *l, void *user_lstate)
{
    discard         resolver;
    discard         user_lstate;
    hpc_tstate_t   *ts = tunnelGetState(owner);
    hps_authority_t authority;
    if (! hpcAllowed(owner, l) || ! selectAuthority(ts, l, false, &authority))
        return false;
    address_context_t *dest = lineGetDestinationAddressContext(l);
    if (authority.literal)
        addresscontextSetIp(dest, &authority.ip);
    else
        addresscontextDomainSet(dest, authority.host, (uint8_t) stringLength(authority.host));
    addresscontextSetPort(dest, authority.port);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    addresscontextSetDomainStrategy(dest, ts->domain_strategy);
    return true;
}

bool hpcBuildRequest(tunnel_t *t, line_t *l)
{
    hpc_tstate_t      *ts   = tunnelGetState(t);
    hpc_lstate_t      *ls   = lineGetState(l, t);
    address_context_t *dest = lineGetDestinationAddressContext(l);
    hps_authority_t    authority;
    if (! selectAuthority(ts, l, ts->resolve_domains, &authority))
        return false;
    char *text = memoryAllocate((size_t) ts->max_header + 1);
    if (! text)
        return false;
    size_t at = 0;
    bool   ok = true;
#define ADD(s)                                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! append(text, ts->max_header, &at, (s)))                                                                  \
        {                                                                                                              \
            ok = false;                                                                                                \
            goto done;                                                                                                 \
        }                                                                                                              \
    } while (0)
    ADD(ts->method);
    ADD(" ");
    if (! ts->connect)
        ADD("http://");
    ADD(authority.wire);
    if (! ts->connect)
        ADD(ts->path);
    ADD(" HTTP/1.1");
    if (at > kHpsRequestLineLimit)
    {
        ok = false;
        goto done;
    }
    ADD("\r\nHost: ");
    ADD(authority.wire);
    ADD("\r\n");
    if (ts->authorization[0])
    {
        ADD("Proxy-Authorization: Basic ");
        ADD(ts->authorization);
        ADD("\r\n");
    }
    if (! ts->connect)
    {
        ADD("Connection: close\r\n");
        if (ts->upload == kHpcBodyFixed)
        {
            char length[64];
            stringNPrintf(length, sizeof(length), "Content-Length: %llu\r\n", (unsigned long long) ts->content_length);
            ADD(length);
        }
        else if (ts->upload == kHpcBodyChunked)
            ADD("Transfer-Encoding: chunked\r\n");
    }
    ADD(ts->headers);
    ADD("\r\n");
    ls->request = hpcBuffer(l, at);
    if (! ls->request)
    {
        ok = false;
        goto done;
    }
    memoryCopy(sbufGetMutablePtr(ls->request), text, at);
    sbufSetLength(ls->request, (uint32_t) at);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
done:
    memoryZero(text, (size_t) ts->max_header + 1);
    memoryFree(text);
    return ok;
#undef ADD
}
