static bool fail_child;
tunnel_t   *__real_nodemanagerCreateTunnelInstance(node_t *child_node);
tunnel_t   *__wrap_nodemanagerCreateTunnelInstance(node_t *child_node);
tunnel_t   *__wrap_nodemanagerCreateTunnelInstance(node_t *child_node)
{
    return fail_child ? NULL : __real_nodemanagerCreateTunnelInstance(child_node);
}
/* Included only by the Linux DNS-wrapped fixture. All payload/close callbacks use
 * the exported resolver entry, with both state slots indexed on the same line. */
static LineDnsResolveFn dns_callback;
static tunnel_t        *dns_tunnel;
static void            *dns_userdata;
static unsigned         lookups;
static int              submit_status;
static char             lookup_name[256];

int __wrap_lineResolveDomainServiceAsync(line_t *l, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata);
int __wrap_lineResolveDomainServiceAsync(line_t *l, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata)
{
    require(l == line && ! service && socktype == SOCK_STREAM, "origin DNS arguments");
    ++lookups;
    stringCopyN(lookup_name, domain, sizeof(lookup_name));
    if (submit_status)
        return submit_status;
    require(! dns_callback, "one origin lookup");
    dns_callback = callback;
    dns_tunnel   = t;
    dns_userdata = userdata;
    lineRef(l);
    return ARES_SUCCESS;
}
static void dnsComplete(int status, const dns_resolved_addr_t *answers, size_t count)
{
    require(dns_callback != NULL, "pending DNS");
    LineDnsResolveFn callback = dns_callback;
    dns_callback              = NULL;
    /* Mirror the framework gate: completion on a dead line only releases its
     * reference. Shared line DNS cancellation tests cover the actual service. */
    if (lineIsAlive(line))
        callback(dns_tunnel, line, dns_userdata, status, "fixture", answers, count);
    lineUnref(line);
}
static dns_resolved_addr_t answer(const char *ip)
{
    address_context_t ctx = {0};
    require(addresscontextSetIpAddress(&ctx, ip), "DNS answer literal");
    sockaddr_u          sa     = addresscontextToSockAddr(&ctx);
    dns_resolved_addr_t result = {0};
    result.family              = addresscontextIsIpv4(&ctx) ? AF_INET : AF_INET6;
    result.addrlen             = result.family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    memoryCopy(&result.addr, &sa, result.addrlen);
    return result;
}
static const char *strategies[] = {"do-not-resolve-domains",
                                   "resolve-domains-and-accept-dns-returned-order",
                                   "resolve-domains-and-prefer-ipv4",
                                   "resolve-domains-and-prefer-ipv6",
                                   "resolve-domains-and-use-only-ipv4",
                                   "resolve-domains-and-use-only-ipv6",
                                   "resolve-domains-with-core-settings"};
static void        dnsOpen(unsigned strategy, bool dynamic_address, bool dynamic_port, const char *target)
{
    char json[768];
    stringNPrintf(json,
                  sizeof(json),
                  "{\"target-address\":\"%s\",\"port\":%s,\"domain-strategy\":\"%s\",\"idle-timeout-ms\":10}",
                  dynamic_address ? "dest_context->address" : target,
                  dynamic_port ? "\"dest_context->port\"" : "443",
                  strategies[strategy]);
    defer_start = true;
    lookups     = 0;
    openLine(json);
    defer_start                 = false;
    address_context_t *dest     = lineGetDestinationAddressContext(line);
    const char        *incoming = dynamic_address ? target : "unused.test";
    if (! addresscontextSetIpAddress(dest, incoming))
        addresscontextDomainSetByString(dest, incoming);
    addresscontextSetPort(dest, dynamic_port ? 8443 : 9443);
}
static void dnsStart(void)
{
    require(entry == tunnelGetBranchEntry(prev, proxy), "exported entry");
    entry->fnInitU(entry, line);
}
static void numericWire(const char *authority)
{
    char expected[640];
    stringNPrintf(expected, sizeof(expected), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority);
    require(next_inits == 1 && writes == 1 && ! stringCompare(sent, expected), "numeric CONNECT and Host snapshot");
}
static void dnsTests(void)
{
    /* The complete strict settings/mode matrix, including construction/destruction. */
    for (unsigned i = 0; i < ARRAY_SIZE(strategies); ++i)
        for (unsigned http = 0; http < 2; ++http)
        {
            char json[512];
            stringNPrintf(json,
                          sizeof(json),
                          "{\"mode\":\"%s\",\"target-address\":\"127.0.0.1\",\"port\":443,\"domain-strategy\":\"%s\"}",
                          http ? "http" : "connect",
                          strategies[i]);
            tunnel_t *t = config(json);
            require((t != NULL) == (! http || i == 0), "strategy/mode matrix");
            if (t)
                httpproxyclientTunnelDestroy(t, wwLifecycleStartupRollback());
        }
    const char *bad[] = {"null",
                         "1",
                         "true",
                         "{}",
                         "[]",
                         "\"\"",
                         "\"prefer-ipv4\"",
                         "\"RESOLVE-DOMAINS-AND-PREFER-IPV4\"",
                         "\"do-not-resolve-domains\",\"domain-strategy\":\"do-not-resolve-domains\""};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        char json[512];
        stringNPrintf(json, sizeof(json), "{\"target-address\":\"x\",\"port\":443,\"domain-strategy\":%s}", bad[i]);
        require(! config(json), "invalid strategy accepted");
    }
    fail_child = true;
    require(! config("{\"target-address\":\"x\",\"port\":443,\"domain-strategy\":\"resolve-domains-and-prefer-ipv4\"}"),
            "helper construction rollback");
    fail_child                 = false;
    dns_resolved_addr_t both[] = {answer("2001:db8::20"), answer("192.0.2.20")};
    GSTATE.domain_strategy     = kDsOnlyIpV4;
    for (unsigned strategy = 1; strategy < ARRAY_SIZE(strategies); ++strategy)
        for (unsigned set = 0; set < 3; ++set)
            for (unsigned mixed = 0; mixed < 4; ++mixed)
            {
                dnsOpen(strategy, mixed & 1, mixed & 2, "origin.test");
                rewrite_target = true;
                dnsStart();
                require(lookups == 1 && ! stringCompare(lookup_name, "origin.test") && ! next_inits && ! writes &&
                            ! ((hpc_tstate_t *) tunnelGetState(proxy))->workers[0].timers,
                        "DNS must precede core Init, timer and transport");
                getWorkerLoop(0)->cur_hrtime += UINT64_C(1000000);
                dnsComplete(ARES_SUCCESS, both + (set == 2), set ? 1 : 2);
                bool v4   = strategy == 2 || strategy == 4 || strategy == 6;
                bool fail = (set == 1 && (strategy == 4 || strategy == 6)) || (set == 2 && strategy == 5);
                if (fail)
                    require(! lineIsAlive(line) && ! next_inits && ! finishes && previous_finishes == 1,
                            "no-family closes only source");
                else
                {
                    char expected[64];
                    stringNPrintf(expected,
                                  sizeof(expected),
                                  "%s:%u",
                                  (set == 2 || (! set && v4)) ? "192.0.2.20" : "[2001:db8::20]",
                                  mixed & 2 ? 8443 : 443);
                    numericWire(expected);
                    hpc_lstate_t *ls = lineGetState(line, proxy);
                    require(ls->timer && ls->progress_at == hpcNow(line), "DNS consumed idle deadline");
                }
                closeLine();
            }
    for (unsigned family = 0; family < 2; ++family)
    {
        dnsOpen(family ? 4 : 5, false, false, family ? "2001:db8::20" : "192.0.2.20");
        dnsStart();
        require(! lookups, "opposite-family literal was resolved/filtered");
        numericWire(family ? "[2001:db8::20]:443" : "192.0.2.20:443");
        closeLine();
    }
    dnsOpen(2, true, true, "origin.test");
    require(dnsstrategyApplyResolvedAddress(lineGetDestinationAddressContext(line), &both[0]), "resolved input");
    dnsStart();
    require(! lookups, "already resolved dynamic target looked up again");
    numericWire("[2001:db8::20]:8443");
    closeLine();
    dnsOpen(0, false, false, "origin.test");
    dnsStart();
    require(! lookups, "default local lookup");
    numericWire("origin.test:443");
    closeLine();
    for (unsigned invalid = 0; invalid < 6; ++invalid)
    {
        dnsOpen(2, true, true, "origin.test");
        address_context_t *dest = lineGetDestinationAddressContext(line);
        if (invalid == 0)
            dest->port = 0;
        if (invalid == 1)
            addresscontextReset(dest);
        if (invalid == 2)
            dest->proto_udp = true;
        if (invalid == 3)
            dest->proto_icmp = true;
        if (invalid == 4)
            dest->proto_packet = true;
        if (invalid == 5)
        {
            addresscontextDomainSetByString(dest, "bad@host");
            dest->port = 443;
        }
        dnsStart();
        require(! lineIsAlive(line) && ! lookups && ! next_inits && ! finishes, "invalid target reached DNS/transport");
        closeLine();
    }
    for (unsigned failure = 0; failure < 5; ++failure)
    {
        dnsOpen(2, false, false, "origin.test");
        submit_status = failure == 0 ? ARES_ENOMEM : 0;
        dnsStart();
        submit_status = 0;
        if (failure)
        {
            sendText(false, "retained");
            if (failure == 3)
                sourceClose();
            if (failure == 4)
                httpproxyclientTunnelOnWorkerQuiesce(proxy, 0, NULL);
            dnsComplete(failure == 1 ? ARES_ENOTFOUND : ARES_SUCCESS, both, failure >= 3 ? 2 : 0);
        }
        require(! lineIsAlive(line) && ! next_inits && ! writes && ! finishes, "DNS failure/close opened transport");
        require(previous_finishes == (failure == 3 ? 0U : 1U), "source Finish reflected");
        closeLine();
    }
    for (unsigned rep = 0; rep < 3; ++rep)
    {
        representation = rep;
        dnsOpen(2, false, false, "origin.test");
        dnsStart();
        sbuf_t   *b        = input("older", 5);
        uintptr_t identity = (uintptr_t) b;
        inject_pause_input = inject_resume_input = true;
        entry->fnPayloadU(entry, line, b);
        source_in_est = init_est = init_pause = true;
        dnsComplete(ARES_SUCCESS, both, 2);
        require(source_paused && ! writes && established == 1, "startup pressure/Est");
        proxy->fnResumeD(proxy, line);
        require(source_paused && writes == 1, "transport Resume cleared protocol/FIFO hold");
        sendText(true, "HTTP/1.1 200 OK\r\n\r\n");
        require(strstr(sent, "\r\n\r\nolderpauseearlyresume") && ! source_paused && (! rep || second_up == identity),
                "resolver FIFO or opaque wrapper lost");
        closeLine();
    }
    representation = 0;
    dnsOpen(2, false, false, "origin.test");
    dnsStart();
    sbuf_t *big = hpcBuffer(line, kHpcDeliveryLimit + 1);
    sbufSetLength(big, kHpcDeliveryLimit + 1);
    entry->fnPayloadU(entry, line, big);
    require(! lineIsAlive(line) && ! next_inits, "resolver overflow");
    dnsComplete(ARES_SUCCESS, both, 2);
    closeLine();
    for (unsigned event = 1; event <= 2; ++event)
    {
        dnsOpen(2, false, false, "origin.test");
        dnsStart();
        init_est     = event == 1;
        init_pause   = event == 2;
        close_signal = event;
        dnsComplete(ARES_SUCCESS, both, 2);
        require(! lineIsAlive(line) && finishes == 1 && ! writes, "resolver reentrant close continued Init");
        closeLine();
    }
    puts("http_proxy_client_dns: passed");
}
