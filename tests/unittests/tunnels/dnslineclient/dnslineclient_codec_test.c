/*
 * Covers: DnsLineClient configuration parsing, the c-ares record codec and the per-worker LRU cache.
 * Setup: Pure functions only; responses are built with the c-ares ares_dns_record API.
 * Cases: config accept/reject, query encode round trip, response validation (id, QR, question, TC, size,
 * rcode mapping), CNAME chains, TTL clamping, cache LRU eviction and expiry.
 * Limits: No lines, workers or event loops; see dnslineclient_flow_test for runtime behaviour.
 * CTest: waterwall.dnslineclient_codec_unit
 */
#include "DnsLineClient/internal.h"
#include "fixtures/assertions.h"

/* ------------------------------------------------------------------------ */
/* config                                                                   */
/* ------------------------------------------------------------------------ */

static bool parseText(const char *text, dnslineclient_mode_e *mode, dnslineclient_config_t *cfg)
{
    cJSON *json = cJSON_Parse(text);
    twfRequire(json != NULL, "test JSON did not parse");
    bool ok = dnslineclientConfigParse(json, "Test->settings", mode, cfg);
    cJSON_Delete(json);
    return ok;
}

static void testConfig(void)
{
    twfSetCase("DnsLineClient config parsing");
    dnslineclient_mode_e   mode;
    dnslineclient_config_t cfg;

    twfRequire(dnslineclientConfigParse(NULL, "Test->settings", &mode, &cfg), "NULL object rejected");
    twfRequire(mode == kDnsLineClientModeCore && cfg.timeout_ms == kDnsLineClientDefaultTimeoutMs &&
                   cfg.tries == kDnsLineClientDefaultTries && cfg.cache_size == kDnsLineClientDefaultCacheSize &&
                   cfg.min_ttl == kDnsLineClientDefaultMinTtl && cfg.max_ttl == kDnsLineClientDefaultMaxTtl &&
                   ! cfg.fallback_to_core && cfg.servers_count == 0,
               "defaults differ from the header");

    twfRequire(parseText("{\"verbose\":true}", &mode, &cfg) && mode == kDnsLineClientModeCore,
               "unrelated keys must be ignored and mode default to core");

    twfRequire(parseText("{\"mode\":\"chain\",\"servers\":[\"1.1.1.1\",\"8.8.8.8:5353\",\"2001:db8::1\","
                         "\"[2001:db8::2]:54\",\"[::1]\"],\"timeout-ms\":500,\"tries\":3,\"cache-size\":0,"
                         "\"min-ttl\":1,\"max-ttl\":10,\"fallback-to-core\":true}",
                         &mode,
                         &cfg),
               "valid chain config rejected");
    twfRequire(mode == kDnsLineClientModeChain && cfg.servers_count == 5 && cfg.timeout_ms == 500 && cfg.tries == 3 &&
                   cfg.cache_size == 0 && cfg.min_ttl == 1 && cfg.max_ttl == 10 && cfg.fallback_to_core,
               "chain config values not stored");
    twfRequire(IP_IS_V4(&cfg.servers[0].ip) && cfg.servers[0].port == 53, "IPv4 default port");
    twfRequire(IP_IS_V4(&cfg.servers[1].ip) && cfg.servers[1].port == 5353, "IPv4 explicit port");
    twfRequire(IP_IS_V6(&cfg.servers[2].ip) && cfg.servers[2].port == 53, "bare IPv6");
    twfRequire(IP_IS_V6(&cfg.servers[3].ip) && cfg.servers[3].port == 54, "bracketed IPv6 with port");
    twfRequire(IP_IS_V6(&cfg.servers[4].ip) && cfg.servers[4].port == 53, "bracketed IPv6 without port");

    static const char *const kRejects[] = {
        "[]",
        "{\"mode\":\"auto\"}",
        "{\"mode\":1}",
        "{\"mode\":\"chain\"}",
        "{\"mode\":\"chain\",\"servers\":[]}",
        "{\"mode\":\"chain\",\"servers\":\"1.1.1.1\"}",
        "{\"mode\":\"chain\",\"servers\":[\"dns.google\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"1.1.1\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"1.1.1.1:0\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"1.1.1.1:65536\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"1.1.1.1:\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"[1.1.1.1]:53\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"[::1]x\"]}",
        "{\"mode\":\"chain\",\"servers\":[\"fe80::1%eth0\"]}",
        "{\"mode\":\"chain\",\"servers\":[5]}",
        ("{\"mode\":\"chain\",\"servers\":[\"1.1.1.1\",\"1.1.1.2\",\"1.1.1.3\",\"1.1.1.4\",\"1.1.1.5\",\"1.1.1.6\","
         "\"1.1.1.7\",\"1.1.1.8\",\"1.1.1.9\"]}"),
        "{\"timeout-ms\":99}",
        "{\"timeout-ms\":60001}",
        "{\"timeout-ms\":\"100\"}",
        "{\"tries\":0}",
        "{\"tries\":17}",
        "{\"cache-size\":-1}",
        "{\"cache-size\":1048577}",
        "{\"min-ttl\":604801}",
        "{\"max-ttl\":1.5}",
        "{\"min-ttl\":100,\"max-ttl\":50}",
        "{\"fallback-to-core\":1}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(kRejects); ++i)
    {
        cfg.tries = 99;
        twfRequire(! parseText(kRejects[i], &mode, &cfg), kRejects[i]);
        twfRequire(cfg.tries == 99, "rejected config modified the output");
    }
}

/* ------------------------------------------------------------------------ */
/* codec                                                                    */
/* ------------------------------------------------------------------------ */

static void testNormalize(void)
{
    twfSetCase("DnsLineClient domain normalization");
    char out[kDnsLineClientMaxDomainLength + 1];
    twfRequire(dnslineclientNormalizeDomain("WWW.Example.COM.", out) && stringCompare(out, "www.example.com") == 0,
               "lowercase/trailing dot");
    twfRequire(! dnslineclientNormalizeDomain("", out) && ! dnslineclientNormalizeDomain(".", out) &&
                   ! dnslineclientNormalizeDomain("a..b", out) && ! dnslineclientNormalizeDomain(".a", out) &&
                   ! dnslineclientNormalizeDomain("a b", out) && ! dnslineclientNormalizeDomain("1.2.3.4", out) &&
                   ! dnslineclientNormalizeDomain("::1", out),
               "invalid names accepted");
    twfRequire(! dnslineclientNormalizeDomain("\\065bc.example", out) && ! dnslineclientNormalizeDomain("a*b.test", out) &&
                   ! dnslineclientNormalizeDomain("a/b.test", out),
               "non-hostname bytes accepted");
    twfRequire(dnslineclientNormalizeDomain("_dmarc.my-host.test", out), "hyphen or underscore rejected");
    char label[80];
    memorySet(label, 'a', 64);
    label[64] = '\0';
    twfRequire(! dnslineclientNormalizeDomain(label, out), "64-byte label accepted");
    label[63] = '\0';
    twfRequire(dnslineclientNormalizeDomain(label, out), "63-byte label rejected");
}

typedef struct test_rr_s
{
    const char         *name;
    ares_dns_rec_type_t type;
    uint32_t            ttl;
    const char         *value; // address text or CNAME target
} test_rr_t;

static unsigned char *buildResponse(uint16_t id, unsigned short flags, ares_dns_rcode_t rcode, const char *qname,
                                    ares_dns_rec_type_t qtype, ares_dns_class_t qclass, const test_rr_t *rrs,
                                    size_t nrrs, size_t *len)
{
    ares_dns_record_t *rec = NULL;
    twfRequire(ares_dns_record_create(&rec, id, flags, ARES_OPCODE_QUERY, rcode) == ARES_SUCCESS, "record create");
    if (qname != NULL)
    {
        twfRequire(ares_dns_record_query_add(rec, qname, qtype, qclass) == ARES_SUCCESS, "query add");
    }
    for (size_t i = 0; i < nrrs; ++i)
    {
        ares_dns_rr_t *rr = NULL;
        twfRequire(ares_dns_record_rr_add(
                       &rr, rec, ARES_SECTION_ANSWER, rrs[i].name, rrs[i].type, ARES_CLASS_IN, rrs[i].ttl) ==
                       ARES_SUCCESS,
                   "rr add");
        if (rrs[i].type == ARES_REC_TYPE_A)
        {
            struct in_addr a;
            twfRequire(inet_pton(AF_INET, rrs[i].value, &a) == 1, "bad test A");
            twfRequire(ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &a) == ARES_SUCCESS, "set A");
        }
        else if (rrs[i].type == ARES_REC_TYPE_AAAA)
        {
            struct ares_in6_addr a6;
            twfRequire(inet_pton(AF_INET6, rrs[i].value, &a6) == 1, "bad test AAAA");
            twfRequire(ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &a6) == ARES_SUCCESS, "set AAAA");
        }
        else
        {
            twfRequire(ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, rrs[i].value) == ARES_SUCCESS, "set CNAME");
        }
    }
    unsigned char *wire = NULL;
    twfRequire(ares_dns_write(rec, &wire, len) == ARES_SUCCESS, "write response");
    ares_dns_record_destroy(rec);
    return wire;
}

static dnslineclient_parse_result_e parse1(const unsigned char *wire, size_t len, uint16_t id,
                                           ares_dns_rec_type_t qtype, dnslineclient_answer_t *out)
{
    return dnslineclientCodecParseResponse(wire, len, "example.test", &id, &qtype, 1, 30, 3600, out);
}

static bool addrIs(const dns_resolved_addr_t *addr, const char *text)
{
    char buf[INET6_ADDRSTRLEN];
    if (addr->family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) &addr->addr;
        return addr->addrlen == sizeof(*sin) && sin->sin_family == AF_INET && sin->sin_port == 0 &&
               inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != NULL && stringCompare(buf, text) == 0;
    }
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) &addr->addr;
    return addr->family == AF_INET6 && addr->addrlen == sizeof(*sin6) && sin6->sin6_family == AF_INET6 &&
           sin6->sin6_port == 0 && inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != NULL &&
           stringCompare(buf, text) == 0;
}

static void testQueryRoundTrip(void)
{
    twfSetCase("DnsLineClient query encode round trip");
    unsigned char *wire = NULL;
    size_t         len  = 0;
    twfRequire(dnslineclientCodecBuildQuery("example.test", 0xBEEF, ARES_REC_TYPE_AAAA, &wire, &len) == ARES_SUCCESS,
               "encode failed");
    ares_dns_record_t *rec = NULL;
    twfRequire(ares_dns_parse(wire, len, 0, &rec) == ARES_SUCCESS, "encoded query does not parse");
    const char         *name   = NULL;
    ares_dns_rec_type_t qtype  = 0;
    ares_dns_class_t    qclass = 0;
    twfRequire(ares_dns_record_get_id(rec) == 0xBEEF && ares_dns_record_get_flags(rec) == ARES_FLAG_RD &&
                   ares_dns_record_get_opcode(rec) == ARES_OPCODE_QUERY && ares_dns_record_query_cnt(rec) == 1 &&
                   ares_dns_record_query_get(rec, 0, &name, &qtype, &qclass) == ARES_SUCCESS &&
                   stringCompare(name, "example.test") == 0 && qtype == ARES_REC_TYPE_AAAA && qclass == ARES_CLASS_IN,
               "encoded query fields");
    twfRequire((wire[2] & 0x80U) == 0 && (wire[2] & 0x01U) != 0, "wire QR/RD bits");
    ares_dns_record_destroy(rec);
    ares_free_string(wire);
}

static void testResponses(void)
{
    twfSetCase("DnsLineClient response validation");
    const unsigned short   ok_flags = ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA;
    dnslineclient_answer_t ans;
    size_t                 len;
    unsigned char         *wire;

    // A answers, min TTL clamped up to min-ttl (30).
    test_rr_t a_rrs[] = {{"example.test", ARES_REC_TYPE_A, 300, "192.0.2.1"},
                         {"EXAMPLE.test", ARES_REC_TYPE_A, 5, "192.0.2.2"},
                         {"other.test", ARES_REC_TYPE_A, 300, "192.0.2.99"},
                         {"example.test", ARES_REC_TYPE_AAAA, 300, "2001:db8::1"}};
    wire =
        buildResponse(7, ok_flags, ARES_RCODE_NOERROR, "Example.Test", ARES_REC_TYPE_A, ARES_CLASS_IN, a_rrs, 4, &len);
    twfRequire(parse1(wire, len, 7, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered, "valid answer ignored");
    twfRequire(ans.status == ARES_SUCCESS && ans.naddrs == 2 && addrIs(&ans.addrs[0], "192.0.2.1") &&
                   addrIs(&ans.addrs[1], "192.0.2.2") && ans.ttl == 30 && ans.addrs[0].ttl == 30,
               "A extraction or TTL clamp-up");
    memoryFree(ans.addrs);

    // Max clamp, AAAA.
    test_rr_t aaaa_rrs[] = {{"example.test", ARES_REC_TYPE_AAAA, 999999, "2001:db8::5"}};
    ares_free_string(wire);
    wire = buildResponse(
        9, ok_flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_AAAA, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseAnswered &&
                   ans.status == ARES_SUCCESS && ans.naddrs == 1 && addrIs(&ans.addrs[0], "2001:db8::5") &&
                   ans.ttl == 3600,
               "AAAA extraction or TTL clamp-down");
    memoryFree(ans.addrs);

    // Id mismatch is ignored, as is a query (QR=0) with the right id.
    twfRequire(parse1(wire, len, 10, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseIgnored, "id mismatch accepted");
    ares_free_string(wire);
    wire = buildResponse(
        9, ARES_FLAG_RD, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_AAAA, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseIgnored, "QR=0 accepted");
    ares_free_string(wire);

    // Question mismatches: name, type, class, missing question.
    wire = buildResponse(
        9, ok_flags, ARES_RCODE_NOERROR, "evil.test", ARES_REC_TYPE_AAAA, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseIgnored, "qname mismatch");
    ares_free_string(wire);
    wire = buildResponse(
        9, ok_flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseIgnored, "qtype mismatch");
    ares_free_string(wire);
    wire = buildResponse(
        9, ok_flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_AAAA, ARES_CLASS_CHAOS, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseIgnored, "qclass mismatch");
    ares_free_string(wire);
    wire = buildResponse(9, ok_flags, ARES_RCODE_NOERROR, NULL, 0, 0, aaaa_rrs, 1, &len);
    // c-ares cannot tie a question-less message to a query; with our id and QR it is a broken answer.
    dnslineclient_parse_result_e no_question = parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans);
    twfRequire(no_question == kDnsLineClientParseIgnored ||
                   (ans.status == ARES_EBADRESP && ans.naddrs == 0 && ans.addrs == NULL),
               "missing question produced addresses");
    ares_free_string(wire);

    // An id-matched error that omits the question ends the try instead of waiting for the timer.
    wire = buildResponse(9, ok_flags, ARES_RCODE_REFUSED, NULL, 0, 0, NULL, 0, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) == kDnsLineClientParseAnswered &&
                   (ans.status == ARES_EREFUSED || ans.status == ARES_EBADRESP) && ans.naddrs == 0,
               "question-less REFUSED did not end the try");
    ares_free_string(wire);
    // NXDOMAIN ends the whole lookup, so it still needs the question.
    wire = buildResponse(9, ok_flags, ARES_RCODE_NXDOMAIN, NULL, 0, 0, NULL, 0, &len);
    twfRequire(parse1(wire, len, 9, ARES_REC_TYPE_AAAA, &ans) != kDnsLineClientParseAnswered ||
                   ans.status != ARES_ENOTFOUND,
               "question-less NXDOMAIN ended the lookup");
    ares_free_string(wire);

    // Rcode mapping.
    static const struct
    {
        ares_dns_rcode_t rcode;
        int              status;
    } kRcodes[] = {{ARES_RCODE_NXDOMAIN, ARES_ENOTFOUND},
                   {ARES_RCODE_SERVFAIL, ARES_ESERVFAIL},
                   {ARES_RCODE_REFUSED, ARES_EREFUSED},
                   {ARES_RCODE_FORMERR, ARES_EFORMERR},
                   {ARES_RCODE_NOTIMP, ARES_ENOTIMP},
                   {ARES_RCODE_YXDOMAIN, ARES_EBADRESP}};
    for (size_t i = 0; i < ARRAY_SIZE(kRcodes); ++i)
    {
        wire =
            buildResponse(3, ok_flags, kRcodes[i].rcode, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, NULL, 0, &len);
        twfRequire(parse1(wire, len, 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered &&
                       ans.status == kRcodes[i].status && ans.naddrs == 0 && ans.addrs == NULL,
                   "rcode mapping");
        ares_free_string(wire);
    }

    // NOERROR without matching records is NODATA.
    wire = buildResponse(
        3, ok_flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(parse1(wire, len, 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered && ans.status == ARES_ENODATA,
               "NODATA");
    ares_free_string(wire);

    // TC=1 fails the slot.
    wire = buildResponse(
        3, ok_flags | ARES_FLAG_TC, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, a_rrs, 1, &len);
    twfRequire(parse1(wire, len, 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered &&
                   ans.status == ARES_EBADRESP && ans.addrs == NULL,
               "TC accepted");

    // Oversized and short datagrams are dropped.
    unsigned char *big = memoryAllocateZero(kDnsLineClientMaxResponseBytes + 1);
    memoryCopy(big, wire, len);
    twfRequire(parse1(big, kDnsLineClientMaxResponseBytes + 1, 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseIgnored,
               "oversized accepted");
    twfRequire(parse1(wire, 11, 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseIgnored, "short accepted");
    memoryFree(big);

    // Garbage carrying our id and QR fails the slot; garbage without our id is noise.
    unsigned char garbage[16] = {0x00, 0x03, 0x80, 0x00, 0xFF, 0xFF};
    twfRequire(parse1(garbage, sizeof(garbage), 3, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered &&
                   ans.status == ARES_EBADRESP,
               "garbage with our id");
    twfRequire(parse1(garbage, sizeof(garbage), 4, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseIgnored,
               "garbage with another id");
    ares_free_string(wire);

    // Two outstanding slots: the matching id selects the slot.
    uint16_t            ids[2]    = {11, 12};
    ares_dns_rec_type_t qtypes[2] = {ARES_REC_TYPE_A, ARES_REC_TYPE_AAAA};
    wire                          = buildResponse(
        12, ok_flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_AAAA, ARES_CLASS_IN, aaaa_rrs, 1, &len);
    twfRequire(dnslineclientCodecParseResponse(wire, len, "example.test", ids, qtypes, 2, 0, 100, &ans) ==
                       kDnsLineClientParseAnswered &&
                   ans.slot == 1 && ans.status == ARES_SUCCESS && ans.ttl == 100,
               "slot selection");
    memoryFree(ans.addrs);
    ares_free_string(wire);
}

static void testCname(void)
{
    twfSetCase("DnsLineClient CNAME chain inside one message");
    const unsigned short   flags = ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA;
    dnslineclient_answer_t ans;
    size_t                 len;

    test_rr_t      chain[] = {{"example.test", ARES_REC_TYPE_CNAME, 600, "alias1.test"},
                              {"alias1.test", ARES_REC_TYPE_CNAME, 40, "Alias2.test"},
                              {"alias2.test", ARES_REC_TYPE_A, 900, "198.51.100.7"},
                              {"unrelated.test", ARES_REC_TYPE_A, 900, "198.51.100.8"}};
    unsigned char *wire =
        buildResponse(5, flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, chain, 4, &len);
    twfRequire(parse1(wire, len, 5, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered &&
                   ans.status == ARES_SUCCESS && ans.naddrs == 1 && addrIs(&ans.addrs[0], "198.51.100.7") &&
                   ans.ttl == 40,
               "CNAME chain or its TTL");
    memoryFree(ans.addrs);
    ares_free_string(wire);

    // A dangling chain (target not in this message) is NODATA; a loop terminates.
    test_rr_t dangling[] = {{"example.test", ARES_REC_TYPE_CNAME, 600, "elsewhere.test"},
                            {"elsewhere2.test", ARES_REC_TYPE_A, 600, "198.51.100.9"}};
    wire =
        buildResponse(5, flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, dangling, 2, &len);
    twfRequire(parse1(wire, len, 5, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered && ans.status == ARES_ENODATA,
               "dangling chain");
    ares_free_string(wire);
    test_rr_t loop[] = {{"example.test", ARES_REC_TYPE_CNAME, 600, "b.test"},
                        {"b.test", ARES_REC_TYPE_CNAME, 600, "example.test"}};
    wire = buildResponse(5, flags, ARES_RCODE_NOERROR, "example.test", ARES_REC_TYPE_A, ARES_CLASS_IN, loop, 2, &len);
    twfRequire(parse1(wire, len, 5, ARES_REC_TYPE_A, &ans) == kDnsLineClientParseAnswered && ans.status == ARES_ENODATA,
               "CNAME loop");
    ares_free_string(wire);
}

/* ------------------------------------------------------------------------ */
/* cache                                                                    */
/* ------------------------------------------------------------------------ */

static dns_resolved_addr_t testAddr(uint8_t last)
{
    dns_resolved_addr_t addr = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in), .ttl = 60};
    struct sockaddr_in *sin  = (struct sockaddr_in *) &addr.addr;
    sin->sin_family          = AF_INET;
    sin->sin_addr.s_addr     = htonl(0xC0000200U | last);
    return addr;
}

static void testCache(void)
{
    twfSetCase("DnsLineClient LRU cache");
    dnslineclient_cache_t cache;
    dns_resolved_addr_t   a1 = testAddr(1), a2 = testAddr(2), a3 = testAddr(3);

    dnslineclientCacheInit(&cache, 0);
    dnslineclientCacheInsert(&cache, "a.test", 1, &a1, 1, 60, 0);
    twfRequire(cache.count == 0 && dnslineclientCacheLookup(&cache, "a.test", 1, 0) == NULL, "disabled cache stored");
    dnslineclientCacheDestroy(&cache);

    dnslineclientCacheInit(&cache, 2);
    dnslineclientCacheInsert(&cache, "a.test", 1, &a1, 1, 10, 1000);
    dnslineclientCacheInsert(&cache, "b.test", 1, &a2, 1, 10, 1000);
    twfRequire(dnslineclientCacheLookup(&cache, "a.test", 3, 1000) == NULL, "qmask is part of the key");
    // Touch a, so b is least recently used.
    const dnslineclient_cache_entry_t *hit = dnslineclientCacheLookup(&cache, "a.test", 1, 1500);
    twfRequire(hit != NULL && hit->naddrs == 1 && memoryEqual(&hit->addrs[0], &a1, sizeof(a1)), "lookup a");
    dnslineclientCacheInsert(&cache, "c.test", 1, &a3, 1, 10, 1500);
    twfRequire(cache.count == 2 && dnslineclientCacheLookup(&cache, "b.test", 1, 1500) == NULL &&
                   dnslineclientCacheLookup(&cache, "a.test", 1, 1500) != NULL &&
                   dnslineclientCacheLookup(&cache, "c.test", 1, 1500) != NULL,
               "LRU eviction removed the wrong entry");

    // Replacement keeps one entry per key.
    dnslineclientCacheInsert(&cache, "a.test", 1, &a2, 1, 10, 2000);
    hit = dnslineclientCacheLookup(&cache, "a.test", 1, 2000);
    twfRequire(cache.count == 2 && hit != NULL && memoryEqual(&hit->addrs[0], &a2, sizeof(a2)), "replacement");

    // Expiry: a expires at 12000, c at 11500.
    twfRequire(dnslineclientCacheLookup(&cache, "c.test", 1, 11499) != NULL, "expired early");
    twfRequire(dnslineclientCacheLookup(&cache, "c.test", 1, 11500) == NULL && cache.count == 1, "did not expire");
    twfRequire(dnslineclientCacheLookup(&cache, "a.test", 1, 12000) == NULL && cache.count == 0, "did not expire a");

    // Zero TTL or empty answers are not stored.
    dnslineclientCacheInsert(&cache, "z.test", 1, &a1, 1, 0, 0);
    dnslineclientCacheInsert(&cache, "z.test", 1, &a1, 0, 10, 0);
    twfRequire(cache.count == 0, "stored a zero-TTL or empty answer");

    // Many entries through a small capacity exercise bucket chains.
    for (unsigned i = 0; i < 100; ++i)
    {
        char name[32];
        snprintf(name, sizeof(name), "n%u.test", i);
        dnslineclientCacheInsert(&cache, name, 1, &a1, 1, 10, 0);
    }
    twfRequire(cache.count == 2 && dnslineclientCacheLookup(&cache, "n99.test", 1, 0) != NULL &&
                   dnslineclientCacheLookup(&cache, "n98.test", 1, 0) != NULL &&
                   dnslineclientCacheLookup(&cache, "n97.test", 1, 0) == NULL,
               "bounded capacity");
    dnslineclientCacheDestroy(&cache);
    twfRequire(cache.count == 0 && cache.buckets == NULL && cache.capacity == 2, "destroy");
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure-random initialization failed");
    twfRequire(frandGlobalInit(), "fast-random global initialization failed");
    frandInit();

    testConfig();
    testNormalize();
    testQueryRoundTrip();
    testResponses();
    testCname();
    testCache();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
