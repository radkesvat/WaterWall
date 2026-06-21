#include "Router/structure.h"
#include "modules/attributes/attributes.h"
#include "modules/destination_domain/destination_domain.h"
#include "modules/protocol/protocol.h"
#include "protocol_sniff.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static line_t *testLineCreate(void)
{
    line_t *line = memoryAllocate(sizeof(*line) + sizeof(router_lstate_t));
    require(line != NULL, "failed to allocate test line");
    memoryZero(line, sizeof(*line) + sizeof(router_lstate_t));
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    addresscontextReset(&line->routing_context.src_ctx);
    addresscontextReset(&line->routing_context.dest_ctx);
    memoryFree(line);
}

static cJSON *parseJsonObject(const char *text)
{
    cJSON *json = cJSON_Parse(text);
    require(json != NULL, "failed to parse test JSON");
    require(cJSON_IsObject(json), "test JSON is not an object");
    return json;
}

static uint32_t makeClientHello(uint8_t *buf, const char *sni)
{
    uint8_t *cursor  = buf;
    uint32_t sni_len = (uint32_t) stringLength(sni);

    *cursor++           = 0x16;
    *cursor++           = 0x03;
    *cursor++           = 0x01;
    uint8_t *record_len = cursor;
    cursor += 2;

    *cursor++          = 0x01;
    uint8_t *hello_len = cursor;
    cursor += 3;

    uint8_t *body = cursor;
    *cursor++     = 0x03;
    *cursor++     = 0x03;
    memorySet(cursor, 0x11, 32);
    cursor += 32;

    *cursor++ = 0;

    PUT_BE16(cursor, 2);
    cursor += 2;
    PUT_BE16(cursor, 0x1301);
    cursor += 2;

    *cursor++ = 1;
    *cursor++ = 0;

    uint8_t *extensions_len = cursor;
    cursor += 2;

    PUT_BE16(cursor, 0x0000);
    cursor += 2;
    PUT_BE16(cursor, (uint16_t) (2U + 3U + sni_len));
    cursor += 2;
    PUT_BE16(cursor, (uint16_t) (3U + sni_len));
    cursor += 2;
    *cursor++ = 0;
    PUT_BE16(cursor, (uint16_t) sni_len);
    cursor += 2;
    memoryCopy(cursor, sni, sni_len);
    cursor += sni_len;

    uint32_t ext_len  = (uint32_t) (cursor - extensions_len - 2);
    uint32_t body_len = (uint32_t) (cursor - body);

    PUT_BE16(extensions_len, (uint16_t) ext_len);
    PUT_BE24(hello_len, body_len);
    PUT_BE16(record_len, (uint16_t) (4U + body_len));

    return (uint32_t) (cursor - buf);
}

static void expectMatch(const char *name, router_match_t got, enum router_classify_result_e result, tunnel_t *target)
{
    if (got.result == result && got.target == target)
    {
        return;
    }

    fprintf(stderr,
            "%s: got result=%d target=%p, expected result=%d target=%p\n",
            name,
            got.result,
            (void *) got.target,
            result,
            (void *) target);
    exit(1);
}

static bool sniffingConfigSucceedsEx(const char *json_text, uint8_t expected_modes,
                                     bool expected_sniff_even_if_domain_is_already_provided)
{
    router_tstate_t ts   = {0};
    cJSON          *json = parseJsonObject(json_text);
    bool            ok   = routerLoadSniffing(&ts, json);
    bool            pass = ok;
    pass                 = pass && ts.sniffing_modes == expected_modes;
    pass = pass && ts.sniff_even_if_domain_is_already_provided == expected_sniff_even_if_domain_is_already_provided;
    cJSON_Delete(json);
    return pass;
}

static bool sniffingConfigSucceeds(const char *json_text, uint8_t expected_modes)
{
    return sniffingConfigSucceedsEx(json_text, expected_modes, false);
}

static bool sniffingConfigFails(const char *json_text)
{
    router_tstate_t ts   = {0};
    cJSON          *json = parseJsonObject(json_text);
    bool            ok   = routerLoadSniffing(&ts, json);
    cJSON_Delete(json);
    return ! ok;
}

static router_rule_t parseDestinationDomainRule(const char *json_text, tunnel_t *target)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerDestinationDomainParse(&rule, json, 0) == kRouterFieldPresent, "destination-domain parse failed");
    rule.target_tunnel = target;
    cJSON_Delete(json);
    return rule;
}

static router_rule_t parseAttributesRule(const char *json_text, tunnel_t *target)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerAttributesParse(&rule, json, 0) == kRouterFieldPresent, "attributes parse failed");
    rule.target_tunnel = target;
    cJSON_Delete(json);
    return rule;
}

static router_rule_t parseProtocolRule(const char *json_text, tunnel_t *target)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerProtocolParse(&rule, json, 0) == kRouterFieldPresent, "protocol parse failed");
    rule.target_tunnel = target;
    cJSON_Delete(json);
    return rule;
}

static bool attributesConfigFails(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    bool          fail = routerAttributesParse(&rule, json, 0) == kRouterFieldError;
    routerAttributesDestroy(&rule);
    cJSON_Delete(json);
    return fail;
}

static bool protocolConfigFails(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    bool          fail = routerProtocolParse(&rule, json, 0) == kRouterFieldError;
    routerProtocolDestroy(&rule);
    cJSON_Delete(json);
    return fail;
}

static router_match_t classifyOneRuleWithState(router_tstate_t *ts, router_rule_t *rule, line_t *line,
                                               router_lstate_t *line_state, const uint8_t *payload,
                                               uint32_t payload_len)
{
    ts->rules       = rule;
    ts->rules_count = 1;

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = line,
        .line_state   = line_state,
        .payload      = payload,
        .payload_len  = payload_len,
    };
    return routerClassify(ts, &mctx);
}

static router_match_t classifyOneRule(router_tstate_t *ts, router_rule_t *rule, line_t *line, const uint8_t *payload,
                                      uint32_t payload_len)
{
    router_lstate_t line_state;
    routerLinestateInitialize(&line_state);
    return classifyOneRuleWithState(ts, rule, line, &line_state, payload, payload_len);
}

static router_match_t classifyNoRules(router_tstate_t *ts, line_t *line, const uint8_t *payload, uint32_t payload_len)
{
    ts->rules       = NULL;
    ts->rules_count = 0;

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = line,
        .payload      = payload,
        .payload_len  = payload_len,
    };
    return routerClassify(ts, &mctx);
}

static void requireDomain(address_context_t *ctx, const char *domain)
{
    uint32_t len = (uint32_t) stringLength(domain);
    require(ctx->domain != NULL, "destination domain was not stored");
    require(ctx->domain_len == len, "destination domain length is wrong");
    require(memoryCompare(ctx->domain, domain, len) == 0, "destination domain content is wrong");
    require(ctx->domain[len] == '\0', "destination domain is not NUL terminated");
}

static void testSniffingConfig(void)
{
    require(sniffingConfigSucceeds("{}", 0), "missing sniffing did not disable sniffing");
    require(sniffingConfigSucceeds("{\"sniffing\":[]}", 0), "empty sniffing did not disable sniffing");
    require(sniffingConfigSucceeds("{\"sniffing\":[\"http1\",\"TLS\",\"http1\"]}", kRouterSniffHttp1 | kRouterSniffTls),
            "valid sniffing modes were not parsed case-insensitively");
    require(sniffingConfigSucceedsEx("{\"sniff-even-if-domain-is-already-provided\":true,\"sniffing\":[\"http1\"]}",
                                     kRouterSniffHttp1,
                                     true),
            "sniff-even-if-domain-is-already-provided=true was not parsed");

    require(sniffingConfigFails("{\"sniffing\":\"http1\"}"), "string sniffing value was accepted");
    require(sniffingConfigFails("{\"sniffing\":[\"http\"]}"), "removed http sniffing value was accepted");
    require(sniffingConfigFails("{\"sniffing\":[1]}"), "non-string sniffing item was accepted");
    require(sniffingConfigFails("{\"sniffing\":[\"client-hello\"]}"), "removed TLS alias was accepted");
    require(sniffingConfigFails("{\"sniffing\":[\"quic\"]}"), "unsupported sniffing value was accepted");
    require(sniffingConfigFails("{\"sniff-even-if-domain-is-already-provided\":\"true\"}"),
            "non-boolean sniff-even-if-domain-is-already-provided was accepted");
    require(attributesConfigFails("{\"attributes\":[]}"), "empty Router attributes array was accepted");
    require(attributesConfigFails("{\"attributes\":[\"typo\"]}"), "unknown Router attribute was accepted");
}

static void testProtocolConfig(void)
{
    require(protocolConfigFails("{\"protocol\":\"http\"}"), "removed protocol value http was accepted");
    require(protocolConfigFails("{\"protocol\":\"quic\"}"), "unsupported protocol value was accepted");
    require(protocolConfigFails("{\"protocol\":[1]}"), "non-string protocol value was accepted");

    router_rule_t rule =
        parseProtocolRule("{\"protocol\":[\"HTTP1\",\"tls\",\"BitTorrent\"]}", (tunnel_t *) (uintptr_t) 0x71);
    uint32_t expected = kAddressContextProtocolHttp1 | kAddressContextProtocolTls | kAddressContextProtocolBittorrent;
    require(rule.protocol.wanted_flags == expected, "protocol parser did not build the expected flag mask");
    routerProtocolDestroy(&rule);
}

static void testProtocolDescriptorTable(void)
{
    uint32_t                            count       = 0;
    const router_protocol_descriptor_t *descriptors = routerProtocolDescriptors(&count);
    uint32_t                            mask        = 0;

    require(count == 3, "Router protocol descriptor count changed unexpectedly");
    for (uint32_t i = 0; i < count; ++i)
    {
        require(descriptors[i].name != NULL, "Router protocol descriptor has no name");
        require(descriptors[i].flag != 0, "Router protocol descriptor has no flag");
        require(descriptors[i].sniff != NULL, "Router protocol descriptor has no sniffer");
        require((mask & descriptors[i].flag) == 0, "Router protocol descriptor flags overlap");
        require(routerProtocolFindDescriptorByName(descriptors[i].name) == &descriptors[i],
                "Router protocol descriptor lookup returned the wrong descriptor");
        mask |= descriptors[i].flag;
    }

    uint32_t expected = kAddressContextProtocolHttp1 | kAddressContextProtocolTls | kAddressContextProtocolBittorrent;
    require(mask == expected, "Router protocol descriptor table does not cover every protocol flag");
    require(routerProtocolFindDescriptorByName("missing") == NULL, "unknown Router protocol descriptor was found");
}

static void testRouterInitClearsOptionalFlags(void)
{
    line_t *line = testLineCreate();
    line->routing_context.dest_ctx.optional_flags.detected_protocols =
        kAddressContextProtocolHttp1 | kAddressContextProtocolBittorrent;

    tunnel_t tunnel      = {0};
    tunnel.lstate_offset = 0;

    routerTunnelUpStreamInit(&tunnel, line);

    router_lstate_t *ls = lineGetState(line, &tunnel);
    require(line->routing_context.dest_ctx.optional_flags.detected_protocols == 0,
            "Router upstream init did not clear destination optional protocol flags");
    require(ls->decided == kRouterRouteUndecided, "Router upstream init did not initialize line state");
    require(ls->pending == NULL, "Router upstream init left pending payload state");

    testLineDestroy(line);
}

static void testHttpSniffingMatchesDestinationDomain(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x10;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.10", 443, IP_PROTO_TCP),
            "failed to set destination IP");
    ip_addr_t original_ip = line->routing_context.dest_ctx.ip_address;

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"api.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp1};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: Api.Example.Test.:443\r\n\r\n";
    expectMatch("http sniffed domain route",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "Api.Example.Test");
    require(dest->type_ip == kCCTypeIp, "sniffed domain changed destination type away from IP");
    require(ipAddrCmp(&dest->ip_address, &original_ip), "sniffed domain changed destination IP");
    require(dest->port == 443, "sniffed domain changed destination port");
    require(dest->proto_tcp, "sniffed domain cleared destination protocol");
    require(dest->domain_resolved, "IP-backed sniffed domain was not marked resolved");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testTlsSniffingMatchesDestinationDomain(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x20;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "198.51.100.20", 443, IP_PROTO_TCP),
            "failed to set destination IP");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"*.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffTls};

    uint8_t  hello[256];
    uint32_t hello_len = makeClientHello(hello, "www.example.test");
    expectMatch(
        "tls sniffed domain route", classifyOneRule(&ts, &rule, line, hello, hello_len), kRouterClassifyTarget, target);

    requireDomain(&line->routing_context.dest_ctx, "www.example.test");
    require(line->routing_context.dest_ctx.domain_resolved, "IP-backed TLS sniffed domain was not marked resolved");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testProtocolHttp1MatchesOnlyHttp1(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x72;

    line_t         *line = testLineCreate();
    router_rule_t   rule = parseProtocolRule("{\"protocol\":\"http1\"}", target);
    router_tstate_t ts   = {.needed_protocols = rule.protocol.wanted_flags};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: protocol.example.test\r\n\r\n";
    expectMatch("http1 protocol route",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolHttp1) != 0,
            "HTTP/1 protocol bit was not set");

    testLineDestroy(line);
    line = testLineCreate();

    const uint8_t http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    expectMatch("http1 does not match HTTP/2 preface",
                classifyOneRule(&ts, &rule, line, http2_preface, (uint32_t) sizeof(http2_preface) - 1U),
                kRouterClassifyDefault,
                NULL);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolHttp1) == 0,
            "HTTP/2 preface set the HTTP/1 protocol bit");

    routerProtocolDestroy(&rule);
    testLineDestroy(line);
}

static void testProtocolBittorrentMatches(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x73;

    line_t         *line = testLineCreate();
    router_rule_t   rule = parseProtocolRule("{\"protocol\":\"bittorrent\"}", target);
    router_tstate_t ts   = {.needed_protocols = rule.protocol.wanted_flags};

    const uint8_t payload[] = {
        19, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', 0x00,
    };

    expectMatch("bittorrent protocol route",
                classifyOneRule(&ts, &rule, line, payload, (uint32_t) sizeof(payload)),
                kRouterClassifyTarget,
                target);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolBittorrent) != 0,
            "BitTorrent protocol bit was not set");

    routerProtocolDestroy(&rule);
    testLineDestroy(line);
}

static void testProtocolBittorrentNeedMore(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x74;

    line_t         *line = testLineCreate();
    router_rule_t   rule = parseProtocolRule("{\"protocol\":\"bittorrent\"}", target);
    router_tstate_t ts   = {.needed_protocols = rule.protocol.wanted_flags};

    const uint8_t partial[] = {19, 'B', 'i', 't'};
    expectMatch("partial bittorrent protocol route",
                classifyOneRule(&ts, &rule, line, partial, (uint32_t) sizeof(partial)),
                kRouterClassifyNeedMore,
                NULL);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolBittorrent) == 0,
            "partial BitTorrent prefix set the protocol bit too early");

    routerProtocolDestroy(&rule);
    testLineDestroy(line);
}

static void testProtocolNonMatchFallsThrough(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x75;

    line_t         *line = testLineCreate();
    router_rule_t   rule = parseProtocolRule("{\"protocol\":\"bittorrent\"}", target);
    router_tstate_t ts   = {.needed_protocols = rule.protocol.wanted_flags};

    const uint8_t payload[] = "GET / HTTP/1.1\r\nHost: other.example.test\r\n\r\n";
    expectMatch("non-bittorrent protocol route",
                classifyOneRule(&ts, &rule, line, payload, (uint32_t) sizeof(payload) - 1U),
                kRouterClassifyDefault,
                NULL);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolBittorrent) == 0,
            "nonmatching payload set the BitTorrent protocol bit");

    routerProtocolDestroy(&rule);
    testLineDestroy(line);
}

static void testProtocolOrMatchesTls(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x76;

    line_t         *line = testLineCreate();
    router_rule_t   rule = parseProtocolRule("{\"protocol\":[\"bittorrent\",\"tls\"]}", target);
    router_tstate_t ts   = {.needed_protocols = rule.protocol.wanted_flags};

    uint8_t  hello[256];
    uint32_t hello_len = makeClientHello(hello, "protocol.example.test");
    expectMatch(
        "protocol OR TLS route", classifyOneRule(&ts, &rule, line, hello, hello_len), kRouterClassifyTarget, target);
    require((line->routing_context.dest_ctx.optional_flags.detected_protocols & kAddressContextProtocolTls) != 0,
            "TLS protocol bit was not set");

    routerProtocolDestroy(&rule);
    testLineDestroy(line);
}

static void testNeedMoreAndWindowLimit(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x30;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.30", 80, IP_PROTO_TCP),
            "failed to set destination IP");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"api.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp1 | kRouterSniffTls};

    const uint8_t partial_http[] = "GET / HTTP/1.1\r\nHo";
    expectMatch("partial http sniff",
                classifyOneRule(&ts, &rule, line, partial_http, (uint32_t) sizeof(partial_http) - 1U),
                kRouterClassifyNeedMore,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "partial HTTP stored a domain");

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    expectMatch("completed http sniff",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);

    addresscontextReset(&line->routing_context.dest_ctx);
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.30", 80, IP_PROTO_TCP),
            "failed to reset destination IP");

    uint8_t  hello[256];
    uint32_t hello_len = makeClientHello(hello, "api.example.test");
    expectMatch("partial tls sniff", classifyOneRule(&ts, &rule, line, hello, 3), kRouterClassifyNeedMore, NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "partial TLS stored a domain");

    expectMatch(
        "completed tls sniff", classifyOneRule(&ts, &rule, line, hello, hello_len), kRouterClassifyTarget, target);

    addresscontextReset(&line->routing_context.dest_ctx);
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.30", 80, IP_PROTO_TCP),
            "failed to reset destination IP after TLS");

    uint8_t too_large[kProtocolSniffMaxWindowBytes];
    memorySet(too_large, 'X', sizeof(too_large));
    too_large[0] = 'G';
    too_large[1] = 'E';
    too_large[2] = 'T';
    too_large[3] = ' ';

    expectMatch("http sniff window exhausted",
                classifyOneRule(&ts, &rule, line, too_large, (uint32_t) sizeof(too_large)),
                kRouterClassifyDefault,
                NULL);

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testSniffingDisabledDoesNotMatchIpOnlyDestination(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x40;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.40", 80, IP_PROTO_TCP),
            "failed to set destination IP");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"api.example.test\"}", target);
    router_tstate_t ts   = {0};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    expectMatch("disabled sniffing",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "disabled sniffing stored a domain");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testDomainOnlyDestinationIsNotSniffedByDefault(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x50;

    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 443);

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"new.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp1};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: new.example.test\r\n\r\n";
    expectMatch("domain-only destination skips sniffing by default",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "old.example.test");
    require(dest->type_ip == kCCTypeDomain, "domain-only destination changed type");
    require(! dest->domain_resolved, "domain-only destination was marked resolved without an IP");
    require(dest->port == 443, "domain-only destination changed port");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testDomainOnlyDestinationCanOptIntoSniffing(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x60;

    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 443);

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"new.example.test\"}", target);
    router_tstate_t ts   = {
          .sniffing_modes                           = kRouterSniffHttp1,
          .sniff_even_if_domain_is_already_provided = true,
    };

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: new.example.test\r\n\r\n";
    expectMatch("domain-only destination opt-in sniffing",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "new.example.test");
    require(dest->type_ip == kCCTypeDomain, "domain-only opt-in changed type");
    require(! dest->domain_resolved, "domain-only opt-in destination was marked resolved without an IP");
    require(dest->port == 443, "domain-only opt-in sniffed domain changed destination port");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testSniffingRunsWithoutRules(void)
{
    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.70", 443, IP_PROTO_TCP),
            "failed to set no-rules destination IP");

    router_tstate_t ts = {.sniffing_modes = kRouterSniffHttp1};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: no-rules.example.test\r\n\r\n";
    expectMatch("no-rules sniffed IP-backed destination",
                classifyNoRules(&ts, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "no-rules.example.test");
    require(dest->type_ip == kCCTypeIp, "no-rules sniffing changed IP-backed destination type");
    require(dest->port == 443, "no-rules sniffing changed destination port");
    require(dest->domain_resolved, "no-rules IP-backed sniffing did not mark domain resolved");

    testLineDestroy(line);
}

static void testNoRulesSniffingRespectsExistingDomainSetting(void)
{
    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: new.example.test\r\n\r\n";

    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 443);

    router_tstate_t guarded = {.sniffing_modes = kRouterSniffHttp1};
    expectMatch("no-rules existing domain skips sniffing by default",
                classifyNoRules(&guarded, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);
    requireDomain(&line->routing_context.dest_ctx, "old.example.test");

    addresscontextReset(&line->routing_context.dest_ctx);
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 443);

    router_tstate_t opt_in = {
        .sniffing_modes                           = kRouterSniffHttp1,
        .sniff_even_if_domain_is_already_provided = true,
    };
    expectMatch("no-rules existing domain opt-in sniffing",
                classifyNoRules(&opt_in, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "new.example.test");
    require(dest->type_ip == kCCTypeDomain, "no-rules opt-in changed domain-backed destination type");
    require(! dest->domain_resolved, "no-rules opt-in marked domain-backed destination resolved");
    require(dest->port == 443, "no-rules opt-in changed destination port");

    testLineDestroy(line);
}

static void testWildcardIpDestinationIsNotMarkedResolved(void)
{
    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "0.0.0.0", 443, IP_PROTO_TCP),
            "failed to set wildcard destination IP");

    router_tstate_t ts = {.sniffing_modes = kRouterSniffHttp1};

    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: wildcard.example.test\r\n\r\n";
    expectMatch("wildcard IP destination sniffing",
                classifyNoRules(&ts, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "wildcard.example.test");
    require(dest->type_ip == kCCTypeIp, "wildcard IP sniffing changed destination type");
    require(addresscontextIsAnyIp(dest), "wildcard IP sniffing changed destination IP");
    require(! dest->domain_resolved, "wildcard IP destination was marked resolved");

    testLineDestroy(line);
}

static void testHttpUpgradeAttributeMatches(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x90;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.90", 80, IP_PROTO_TCP),
            "failed to set upgrade destination IP");

    router_rule_t   rule = parseAttributesRule("{\"attributes\":[\"http_upgrade_present\"]}", target);
    router_tstate_t ts   = {
          .sniffing_modes               = kRouterSniffHttp1,
          .needs_http_upgrade_attribute = true,
    };
    router_lstate_t line_state;
    routerLinestateInitialize(&line_state);

    const uint8_t request[] = "GET /chat HTTP/1.1\r\n"
                              "Host: upgrade.example.test\r\n"
                              "Connection: keep-alive, Upgrade\r\n"
                              "Upgrade: websocket\r\n"
                              "\r\n";
    expectMatch("http upgrade attribute route",
                classifyOneRuleWithState(&ts, &rule, line, &line_state, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);
    require((line_state.sniffed_attributes & kRouterAttributeHttpUpgradePresent) != 0,
            "HTTP Upgrade header did not set the line-state attribute bit");

    routerAttributesDestroy(&rule);
    testLineDestroy(line);
}

static void testHttpUpgradeAttributeMissingDoesNotMatch(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x91;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.91", 80, IP_PROTO_TCP),
            "failed to set no-upgrade destination IP");

    router_rule_t   rule = parseAttributesRule("{\"attributes\":[\"http_upgrade_present\"]}", target);
    router_tstate_t ts   = {
          .sniffing_modes               = kRouterSniffHttp1,
          .needs_http_upgrade_attribute = true,
    };
    router_lstate_t line_state;
    routerLinestateInitialize(&line_state);

    const uint8_t request[] = "GET /plain HTTP/1.1\r\n"
                              "Host: plain.example.test\r\n"
                              "Connection: keep-alive\r\n"
                              "\r\n";
    expectMatch("missing http upgrade attribute route",
                classifyOneRuleWithState(&ts, &rule, line, &line_state, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyDefault,
                NULL);
    require((line_state.sniffed_attributes & kRouterAttributeHttpUpgradePresent) == 0,
            "HTTP Upgrade attribute bit was set without an Upgrade header");

    routerAttributesDestroy(&rule);
    testLineDestroy(line);
}

static void testHttpUpgradeAttributeSniffsWhenDestinationDomainExists(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x92;

    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 80);

    router_rule_t   rule = parseAttributesRule("{\"attributes\":[\"http_upgrade_present\"]}", target);
    router_tstate_t ts   = {
          .sniffing_modes               = kRouterSniffHttp1,
          .needs_http_upgrade_attribute = true,
    };
    router_lstate_t line_state;
    routerLinestateInitialize(&line_state);

    const uint8_t request[] = "GET /socket HTTP/1.1\r\n"
                              "Host: new.example.test\r\n"
                              "Upgrade: websocket\r\n"
                              "\r\n";
    expectMatch("http upgrade attribute with existing domain",
                classifyOneRuleWithState(&ts, &rule, line, &line_state, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);
    require((line_state.sniffed_attributes & kRouterAttributeHttpUpgradePresent) != 0,
            "HTTP Upgrade attribute bit was not set when destination domain already existed");
    requireDomain(&line->routing_context.dest_ctx, "old.example.test");

    routerAttributesDestroy(&rule);
    testLineDestroy(line);
}

static void testHttpUpgradeAttributeNeedMore(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x93;

    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "old.example.test");
    addresscontextSetPort(&line->routing_context.dest_ctx, 80);

    router_rule_t   rule = parseAttributesRule("{\"attributes\":[\"http_upgrade_present\"]}", target);
    router_tstate_t ts   = {
          .sniffing_modes               = kRouterSniffHttp1,
          .needs_http_upgrade_attribute = true,
    };
    router_lstate_t line_state;
    routerLinestateInitialize(&line_state);

    const uint8_t partial[] = "GET /socket HTTP/1.1\r\nUpgrade";
    expectMatch("partial http upgrade attribute route",
                classifyOneRuleWithState(&ts, &rule, line, &line_state, partial, (uint32_t) sizeof(partial) - 1U),
                kRouterClassifyNeedMore,
                NULL);
    require((line_state.sniffed_attributes & kRouterAttributeHttpUpgradePresent) == 0,
            "partial HTTP Upgrade header set the attribute bit too early");

    routerAttributesDestroy(&rule);
    testLineDestroy(line);
}

int main(void)
{
    testSniffingConfig();
    testProtocolConfig();
    testProtocolDescriptorTable();
    testRouterInitClearsOptionalFlags();
    testHttpSniffingMatchesDestinationDomain();
    testTlsSniffingMatchesDestinationDomain();
    testProtocolHttp1MatchesOnlyHttp1();
    testProtocolBittorrentMatches();
    testProtocolBittorrentNeedMore();
    testProtocolNonMatchFallsThrough();
    testProtocolOrMatchesTls();
    testNeedMoreAndWindowLimit();
    testSniffingDisabledDoesNotMatchIpOnlyDestination();
    testDomainOnlyDestinationIsNotSniffedByDefault();
    testDomainOnlyDestinationCanOptIntoSniffing();
    testSniffingRunsWithoutRules();
    testNoRulesSniffingRespectsExistingDomainSetting();
    testWildcardIpDestinationIsNotMarkedResolved();
    testHttpUpgradeAttributeMatches();
    testHttpUpgradeAttributeMissingDoesNotMatch();
    testHttpUpgradeAttributeSniffsWhenDestinationDomainExists();
    testHttpUpgradeAttributeNeedMore();
    return 0;
}
