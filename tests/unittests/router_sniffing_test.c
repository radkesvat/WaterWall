#include "Router/structure.h"
#include "modules/attributes/attributes.h"
#include "modules/destination_domain/destination_domain.h"
#include "modules/destination_port/destination_port.h"
#include "modules/password/password.h"
#include "modules/protocol/protocol.h"
#include "modules/source_port/source_port.h"
#include "modules/username/username.h"
#include "generic_sniffer.h"

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
#include "Router/http2_sniffing.h"
#include <nghttp2/nghttp2.h>
#endif

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
#include "Router/quic_sniffing.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#ifndef ROUTER_QUIC_SNI_VECTOR_DIR
#define ROUTER_QUIC_SNI_VECTOR_DIR "fixtures/router_quic_sni/vectors"
#endif

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
    line_t *line = memoryAllocateZero(sizeof(*line) + sizeof(router_lstate_t));
    require(line != NULL, "failed to allocate test line");
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    addresscontextReset(&line->routing_context.src_ctx);
    addresscontextReset(&line->routing_context.dest_ctx);
    lineClearUsers(line);
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

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
static void appendHttp2Wire(uint8_t **wire, size_t *wire_len, size_t *wire_cap, const uint8_t *data, size_t data_len)
{
    if (*wire_len + data_len > *wire_cap)
    {
        size_t new_cap = *wire_cap == 0 ? 1024U : *wire_cap;
        while (*wire_len + data_len > new_cap)
        {
            new_cap *= 2U;
        }

        uint8_t *grown = realloc(*wire, new_cap);
        require(grown != NULL, "realloc failed while collecting HTTP/2 test request");
        *wire     = grown;
        *wire_cap = new_cap;
    }

    memoryCopy(*wire + *wire_len, data, data_len);
    *wire_len += data_len;
}

static uint32_t makeHttp2PriorKnowledgeRequest(uint8_t **out_wire, const char *authority)
{
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_session           *client    = NULL;

    require(nghttp2_session_callbacks_new(&callbacks) == 0, "HTTP/2 client callbacks allocation failed");
    require(nghttp2_session_client_new(&client, callbacks, NULL) == 0, "HTTP/2 client session allocation failed");

    require(nghttp2_submit_settings(client, NGHTTP2_FLAG_NONE, NULL, 0) == 0, "HTTP/2 client settings submit failed");

    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority",
         (uint8_t *) authority,
         10,
         stringLength(authority),
         NGHTTP2_NV_FLAG_NONE},
    };

    int32_t stream_id = nghttp2_submit_request(client, NULL, headers, ARRAY_SIZE(headers), NULL, NULL);
    require(stream_id > 0, "HTTP/2 request submit failed");

    uint8_t *wire     = NULL;
    size_t   wire_len = 0;
    size_t   wire_cap = 0;

    while (true)
    {
        const uint8_t *data = NULL;
        nghttp2_ssize  len  = nghttp2_session_mem_send2(client, &data);
        require(len >= 0, "HTTP/2 client mem_send failed");
        if (len == 0)
        {
            break;
        }
        appendHttp2Wire(&wire, &wire_len, &wire_cap, data, (size_t) len);
    }

    require(wire_len > 24U, "HTTP/2 prior-knowledge request did not include frames");
    require(wire_len <= UINT32_MAX, "HTTP/2 prior-knowledge request is too large");

    nghttp2_session_del(client);
    nghttp2_session_callbacks_del(callbacks);

    *out_wire = wire;
    return (uint32_t) wire_len;
}
#endif

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

static router_rule_t parseSourcePortRule(const char *json_text, tunnel_t *target)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerSourcePortParse(&rule, json, 0) == kRouterFieldPresent, "source-port parse failed");
    rule.target_tunnel = target;
    cJSON_Delete(json);
    return rule;
}

static router_rule_t parseDestinationPortRule(const char *json_text, tunnel_t *target)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerDestinationPortParse(&rule, json, 0) == kRouterFieldPresent, "destination-port parse failed");
    rule.target_tunnel = target;
    cJSON_Delete(json);
    return rule;
}

static router_rule_t parseAuthenticatedIdentityRule(const char *json_text)
{
    router_rule_t       rule            = {0};
    cJSON              *json            = parseJsonObject(json_text);
    router_field_parse_t username_result = routerUsernameParse(&rule, json, 0);
    router_field_parse_t password_result = routerPasswordParse(&rule, json, 0);

    require(username_result != kRouterFieldError, "username parse failed");
    require(password_result != kRouterFieldError, "password parse failed");
    require(username_result == kRouterFieldPresent || password_result == kRouterFieldPresent,
            "authenticated identity rule had no username or password");
    cJSON_Delete(json);
    return rule;
}

static void destroyAuthenticatedIdentityRule(router_rule_t *rule)
{
    routerUsernameDestroy(rule);
    routerPasswordDestroy(rule);
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

static bool sourcePortConfigFails(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    bool          fail = routerSourcePortParse(&rule, json, 0) == kRouterFieldError;
    routerSourcePortDestroy(&rule);
    cJSON_Delete(json);
    return fail;
}

static bool destinationPortConfigFails(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    bool          fail = routerDestinationPortParse(&rule, json, 0) == kRouterFieldError;
    routerDestinationPortDestroy(&rule);
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
#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
    require(sniffingConfigSucceeds("{\"sniffing\":[\"HTTP2\"]}", kRouterSniffHttp2),
            "HTTP/2 sniffing mode was not parsed when Router HTTP/2 sniffing is enabled");
    require(sniffingConfigSucceeds("{\"sniffing\":[\"http\"]}", kRouterSniffHttp1 | kRouterSniffHttp2),
            "http sniffing alias did not expand to HTTP/1 + HTTP/2");
#else
    require(sniffingConfigFails("{\"sniffing\":[\"http2\"]}"),
            "HTTP/2 sniffing mode was accepted when Router HTTP/2 sniffing is disabled");
    require(sniffingConfigFails("{\"sniffing\":[\"http\"]}"),
            "http sniffing alias was accepted when Router HTTP/2 sniffing is disabled");
#endif
#ifdef ROUTER_ENABLE_QUIC_SNIFFING
    require(sniffingConfigSucceeds("{\"sniffing\":[\"QUIC\"]}", kRouterSniffQuic),
            "QUIC sniffing mode was not parsed when Router QUIC sniffing is enabled");
    require(sniffingConfigSucceeds("{\"sniffing\":[\"http3\"]}", kRouterSniffQuic),
            "HTTP/3 sniffing alias was not parsed as QUIC when Router QUIC sniffing is enabled");
#else
    require(sniffingConfigFails("{\"sniffing\":[\"quic\"]}"),
            "QUIC sniffing mode was accepted when Router QUIC sniffing is disabled");
    require(sniffingConfigFails("{\"sniffing\":[\"http3\"]}"),
            "HTTP/3 sniffing alias was accepted when Router QUIC sniffing is disabled");
#endif
#if defined(ROUTER_ENABLE_HTTP2_SNIFFING) && defined(ROUTER_ENABLE_QUIC_SNIFFING)
    require(sniffingConfigSucceeds("{\"sniffing\":[\"http\",\"http3\"]}",
                                   kRouterSniffHttp1 | kRouterSniffHttp2 | kRouterSniffQuic),
            "http + http3 sniffing aliases did not include all expected HTTP versions");
#endif
    require(sniffingConfigSucceedsEx("{\"sniff-even-if-domain-is-already-provided\":true,\"sniffing\":[\"http1\"]}",
                                     kRouterSniffHttp1,
                                     true),
            "sniff-even-if-domain-is-already-provided=true was not parsed");

    require(sniffingConfigFails("{\"sniffing\":\"http1\"}"), "string sniffing value was accepted");
    require(sniffingConfigFails("{\"sniffing\":[1]}"), "non-string sniffing item was accepted");
    require(sniffingConfigFails("{\"sniffing\":[\"client-hello\"]}"), "removed TLS alias was accepted");
    require(sniffingConfigFails("{\"sniff-even-if-domain-is-already-provided\":\"true\"}"),
            "non-boolean sniff-even-if-domain-is-already-provided was accepted");
    require(attributesConfigFails("{\"attributes\":[]}"), "empty Router attributes array was accepted");
    require(attributesConfigFails("{\"attributes\":[\"typo\"]}"), "unknown Router attribute was accepted");
}

#ifdef ROUTER_ENABLE_QUIC_SNIFFING
static void testQuicSniffingRejectsNonQuicPayload(void)
{
    uint8_t  host[UINT8_MAX + 1U];
    uint32_t host_len = 0;

    const uint8_t http[] = "GET / HTTP/1.1\r\nHost: not-quic.example.test\r\n\r\n";
    require(routerQuicSniffClientHelloSni(http, (uint32_t) sizeof(http) - 1U, host, (uint32_t) sizeof(host),
                                          &host_len) == kGenericSnifferMissing,
            "QUIC sniffing treated HTTP payload as QUIC");
    require(host_len == 0, "QUIC sniffing filled host for non-QUIC payload");

    const uint8_t partial_quic_long_header[] = {0xc3, 0x00};
    require(routerQuicSniffClientHelloSni(partial_quic_long_header, (uint32_t) sizeof(partial_quic_long_header), host,
                                          (uint32_t) sizeof(host), &host_len) == kGenericSnifferMissing,
            "partial QUIC long-header payload asked Router to keep buffering");

    const uint8_t truncated_v1_initial[] = {
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x40, 0x20,
    };
    require(routerQuicSniffClientHelloSni(truncated_v1_initial, (uint32_t) sizeof(truncated_v1_initial), host,
                                          (uint32_t) sizeof(host), &host_len) == kGenericSnifferMissing,
            "truncated QUIC v1 Initial asked Router to keep buffering");

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.53", 443, IP_PROTO_UDP),
            "failed to set UDP destination IP for QUIC sniffing test");

    router_tstate_t ts = {.sniffing_modes = kRouterSniffQuic};
    expectMatch("truncated UDP QUIC sniff falls through",
                classifyNoRules(&ts, line, truncated_v1_initial, (uint32_t) sizeof(truncated_v1_initial)),
                kRouterClassifyDefault,
                NULL);

    addresscontextReset(&line->routing_context.dest_ctx);
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.53", 443, IP_PROTO_TCP),
            "failed to set TCP destination IP for QUIC sniffing test");
    expectMatch("QUIC sniff skipped on TCP",
                classifyNoRules(&ts, line, truncated_v1_initial, (uint32_t) sizeof(truncated_v1_initial)),
                kRouterClassifyDefault,
                NULL);

    testLineDestroy(line);
}

typedef struct quic_vector_buffer_s
{
    uint8_t *data;
    uint32_t len;
    uint32_t cap;
} quic_vector_buffer_t;

static const char *quicSniffResultName(generic_sniffer_result_t result)
{
    switch (result)
    {
    case kGenericSnifferFound:
        return "Found";
    case kGenericSnifferNeedMore:
        return "NeedMore";
    case kGenericSnifferMissing:
        return "Missing";
    default:
        return "Unknown";
    }
}

static void quicVectorFail(const char *name, const char *expect, generic_sniffer_result_t result,
                           const uint8_t *domain, const char *want_domain, const char *comment)
{
    fprintf(stderr,
            "QUIC vector %s failed: expect=%s got=%s domain='%s' want='%s' note=%s\n",
            name,
            expect,
            quicSniffResultName(result),
            domain != NULL ? (const char *) domain : "",
            want_domain,
            comment);
    exit(1);
}

static void quicVectorPath(char *out, size_t out_len, const char *file_name)
{
    int written = snprintf(out, out_len, "%s/%s", ROUTER_QUIC_SNI_VECTOR_DIR, file_name);
    require(written > 0 && (size_t) written < out_len, "QUIC vector path is too long");
}

static uint8_t *readQuicVectorFile(const char *file_name, uint32_t *out_len)
{
    char path[1024];
    quicVectorPath(path, sizeof(path), file_name);

    FILE *f = fopen(path, "rb");
    require(f != NULL, "failed to open QUIC vector fixture");
    require(fseek(f, 0, SEEK_END) == 0, "failed to seek QUIC vector fixture");
    long file_size = ftell(f);
    require(file_size >= 0, "failed to tell QUIC vector fixture size");
    require(file_size <= (long) UINT32_MAX, "QUIC vector fixture is too large");
    rewind(f);

    uint32_t len = (uint32_t) file_size;
    uint8_t *buf = memoryAllocate(len == 0 ? 1U : len);
    require(buf != NULL, "failed to allocate QUIC vector fixture buffer");
    if (len > 0)
    {
        require(fread(buf, 1, len, f) == len, "failed to read QUIC vector fixture");
    }
    fclose(f);

    *out_len = len;
    return buf;
}

static void quicVectorAppend(quic_vector_buffer_t *buffer, const uint8_t *data, uint32_t data_len)
{
    require(data_len <= UINT32_MAX - buffer->len, "QUIC vector accumulated payload is too large");
    uint32_t need = buffer->len + data_len;
    if (need > buffer->cap)
    {
        uint32_t new_cap = buffer->cap == 0 ? 4096U : buffer->cap;
        while (new_cap < need)
        {
            require(new_cap <= UINT32_MAX / 2U, "QUIC vector accumulated payload capacity overflowed");
            new_cap *= 2U;
        }
        uint8_t *grown = memoryReAllocate(buffer->data, new_cap);
        require(grown != NULL, "failed to grow QUIC vector accumulated payload");
        buffer->data = grown;
        buffer->cap  = new_cap;
    }

    if (data_len > 0)
    {
        memoryCopy(buffer->data + buffer->len, data, data_len);
        buffer->len = need;
    }
}

static void quicVectorTrimLine(char *line)
{
    uint32_t len = (uint32_t) stringLength(line);
    while (len > 0 && (line[len - 1U] == '\n' || line[len - 1U] == '\r'))
    {
        line[--len] = '\0';
    }
}

static bool quicVectorSplitManifestLine(char *line, char **fields, uint32_t fields_count)
{
    char *cursor = line;
    for (uint32_t i = 0; i < fields_count; ++i)
    {
        fields[i] = cursor;
        if (i == fields_count - 1U)
        {
            return true;
        }

        char *bar = stringChr(cursor, '|');
        if (bar == NULL)
        {
            return false;
        }
        *bar   = '\0';
        cursor = bar + 1;
    }

    return true;
}

static bool quicVectorNextFile(char **cursor, const char **file_name)
{
    if (*cursor == NULL || **cursor == '\0')
    {
        return false;
    }

    char *start = *cursor;
    char *comma = stringChr(start, ',');
    if (comma != NULL)
    {
        *comma  = '\0';
        *cursor = comma + 1;
    }
    else
    {
        *cursor = NULL;
    }

    *file_name = start;
    return true;
}

static bool quicVectorFinalResultMatches(const char *expect, generic_sniffer_result_t result, const uint8_t *domain,
                                         uint32_t domain_len, const char *want_domain)
{
    bool domain_empty = domain_len == 0 && domain[0] == '\0';
    if (stringCompare(expect, "OK") == 0)
    {
        uint32_t want_len = (uint32_t) stringLength(want_domain);
        return result == kGenericSnifferFound && domain_len == want_len &&
               memoryCompare(domain, want_domain, want_len) == 0 && domain[want_len] == '\0';
    }
    if (stringCompare(expect, "NO_SNI") == 0)
    {
        return result == kGenericSnifferMissing && domain_empty;
    }
    if (stringCompare(expect, "FAIL") == 0)
    {
        return result != kGenericSnifferFound && domain_empty;
    }
    if (stringCompare(expect, "NEED_MORE_OR_FAIL") == 0)
    {
        return (result == kGenericSnifferNeedMore || result == kGenericSnifferMissing) && domain_empty;
    }
    if (stringCompare(expect, "UNSUPPORTED_OR_FAIL") == 0)
    {
        return result != kGenericSnifferFound && domain_empty;
    }

    return false;
}

static void runQuicVectorCase(char *line)
{
    char *fields[5] = {0};
    require(quicVectorSplitManifestLine(line, fields, ARRAY_SIZE(fields)), "malformed QUIC vector manifest line");

    const char *name        = fields[0];
    const char *expect      = fields[1];
    const char *want_domain = fields[2];
    char       *files_csv   = fields[3];
    const char *comment     = fields[4];

    quic_vector_buffer_t accumulated = {0};
    generic_sniffer_result_t result  = kGenericSnifferMissing;
    uint8_t domain[UINT8_MAX + 1U];
    uint32_t domain_len = 0;
    domain[0]           = '\0';

    char       *cursor = files_csv;
    const char *file_name;
    while (quicVectorNextFile(&cursor, &file_name))
    {
        require(file_name[0] != '\0', "empty QUIC vector fixture file name");

        uint32_t file_len = 0;
        uint8_t *file     = readQuicVectorFile(file_name, &file_len);
        quicVectorAppend(&accumulated, file, file_len);
        memoryFree(file);

        result = routerQuicSniffClientHelloSni(accumulated.data,
                                               accumulated.len,
                                               domain,
                                               (uint32_t) sizeof(domain),
                                               &domain_len);

        bool has_more_files = cursor != NULL && cursor[0] != '\0';
        if (has_more_files && stringCompare(expect, "OK") == 0 && result != kGenericSnifferNeedMore)
        {
            quicVectorFail(name, "intermediate NeedMore", result, domain, want_domain, comment);
        }
    }

    if (! quicVectorFinalResultMatches(expect, result, domain, domain_len, want_domain))
    {
        quicVectorFail(name, expect, result, domain, want_domain, comment);
    }

    memoryFree(accumulated.data);
}

static void testQuicVectorFixtures(void)
{
    char manifest[1024];
    quicVectorPath(manifest, sizeof(manifest), "manifest.txt");

    FILE *f = fopen(manifest, "r");
    require(f != NULL, "failed to open QUIC vector manifest");

    char     line[4096];
    uint32_t total = 0;
    while (fgets(line, sizeof(line), f) != NULL)
    {
        quicVectorTrimLine(line);
        if (line[0] == '\0' || line[0] == '#')
        {
            continue;
        }

        ++total;
        runQuicVectorCase(line);
    }
    fclose(f);

    require(total > 0, "QUIC vector manifest did not contain any test cases");
}

static void testQuicHttp3AliasRoutesVector(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x26;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.26", 443, IP_PROTO_UDP),
            "failed to set UDP destination IP for HTTP/3 vector test");
    ip_addr_t original_ip = line->routing_context.dest_ctx.ip_address;

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"basic.example\"}", target);
    router_tstate_t ts   = {0};
    cJSON          *json = parseJsonObject("{\"sniffing\":[\"http3\"]}");
    require(routerLoadSniffing(&ts, json), "HTTP/3 sniffing alias config failed");
    cJSON_Delete(json);
    require(ts.sniffing_modes == kRouterSniffQuic, "HTTP/3 sniffing alias did not enable QUIC sniffing");

    uint32_t vector_len = 0;
    uint8_t *vector     = readQuicVectorFile("01_single_initial.bin", &vector_len);
    expectMatch("HTTP/3 alias routed QUIC SNI",
                classifyOneRule(&ts, &rule, line, vector, vector_len),
                kRouterClassifyTarget,
                target);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "basic.example");
    require(dest->type_ip == kCCTypeIp, "HTTP/3 sniffed domain changed destination type away from IP");
    require(ipAddrCmp(&dest->ip_address, &original_ip), "HTTP/3 sniffed domain changed destination IP");
    require(dest->port == 443, "HTTP/3 sniffed domain changed destination port");
    require(dest->proto_udp, "HTTP/3 sniffed domain cleared destination UDP protocol");
    require(dest->domain_resolved, "IP-backed HTTP/3 sniffed domain was not marked resolved");

    memoryFree(vector);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testQuicSniffingSkippedOnTcpVector(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x27;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.27", 443, IP_PROTO_TCP),
            "failed to set TCP destination IP for QUIC vector test");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"basic.example\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffQuic};

    uint32_t vector_len = 0;
    uint8_t *vector     = readQuicVectorFile("01_single_initial.bin", &vector_len);
    expectMatch("QUIC vector sniff skipped on TCP",
                classifyOneRule(&ts, &rule, line, vector, vector_len),
                kRouterClassifyDefault,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "TCP QUIC vector sniffing stored a domain");

    memoryFree(vector);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testQuicBadVectorFallsThrough(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x28;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.28", 443, IP_PROTO_UDP),
            "failed to set UDP destination IP for bad QUIC vector test");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"basic.example\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffQuic};

    uint32_t vector_len = 0;
    uint8_t *vector     = readQuicVectorFile("14_bad_gcm_tag.bin", &vector_len);
    expectMatch("bad QUIC vector falls through",
                classifyOneRule(&ts, &rule, line, vector, vector_len),
                kRouterClassifyDefault,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "bad QUIC vector stored a domain");

    memoryFree(vector);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}
#endif

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

static void testPortMatchers(void)
{
    require(sourcePortConfigFails("{\"source-port\":\"443\"}"), "string source-port was accepted");
    require(sourcePortConfigFails("{\"source-port\":[80,\"443\"]}"), "non-integer source-port array item was accepted");
    require(sourcePortConfigFails("{\"source-port\":[]}"), "empty source-port array was accepted");
    require(sourcePortConfigFails("{\"source-port\":70000}"), "out-of-range source-port was accepted");
    require(sourcePortConfigFails("{\"source-port-range\":443}"), "non-array source-port-range was accepted");
    require(sourcePortConfigFails("{\"source-port-range\":[1000]}"),
            "single-element source-port-range was accepted");
    require(sourcePortConfigFails("{\"source-port-range\":[2000,1000]}"),
            "descending source-port-range was accepted");
    require(destinationPortConfigFails("{\"destination-port\":\"443\"}"), "string destination-port was accepted");
    require(destinationPortConfigFails("{\"destination-port\":-1}"), "negative destination-port was accepted");
    require(destinationPortConfigFails("{\"destination-port-range\":[80,443,8443]}"),
            "three-element destination-port-range was accepted");
    require(destinationPortConfigFails("{\"destination-port-range\":[80,443.5]}"),
            "fractional destination-port-range element was accepted");

    tunnel_t *source_target = (tunnel_t *) (uintptr_t) 0x81;
    line_t   *line         = testLineCreate();

    router_rule_t   source_rule =
        parseSourcePortRule("{\"source-port\":[80,443],\"source-port-range\":[1000,1002]}", source_target);
    router_tstate_t ts = {0};

    addresscontextSetPort(&line->routing_context.src_ctx, 80);
    expectMatch("source exact port route",
                classifyOneRule(&ts, &source_rule, line, NULL, 0),
                kRouterClassifyTarget,
                source_target);

    addresscontextSetPort(&line->routing_context.src_ctx, 1002);
    expectMatch("source inclusive high port route",
                classifyOneRule(&ts, &source_rule, line, NULL, 0),
                kRouterClassifyTarget,
                source_target);

    addresscontextSetPort(&line->routing_context.src_ctx, 999);
    expectMatch("source port nonmatch route",
                classifyOneRule(&ts, &source_rule, line, NULL, 0),
                kRouterClassifyDefault,
                NULL);

    routerSourcePortDestroy(&source_rule);
    testLineDestroy(line);

    tunnel_t *destination_target = (tunnel_t *) (uintptr_t) 0x82;
    line                       = testLineCreate();

    router_rule_t destination_rule =
        parseDestinationPortRule("{\"destination-port\":[53,443],\"destination-port-range\":[8000,8002]}",
                                 destination_target);

    addresscontextSetPort(&line->routing_context.dest_ctx, 53);
    expectMatch("destination exact port route",
                classifyOneRule(&ts, &destination_rule, line, NULL, 0),
                kRouterClassifyTarget,
                destination_target);

    addresscontextSetPort(&line->routing_context.dest_ctx, 8001);
    expectMatch("destination range middle port route",
                classifyOneRule(&ts, &destination_rule, line, NULL, 0),
                kRouterClassifyTarget,
                destination_target);

    addresscontextSetPort(&line->routing_context.dest_ctx, 1500);
    expectMatch("destination exact list is not a range",
                classifyOneRule(&ts, &destination_rule, line, NULL, 0),
                kRouterClassifyDefault,
                NULL);

    routerDestinationPortDestroy(&destination_rule);
    testLineDestroy(line);
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
    require(ls->route == kRouterRouteUndecided, "Router upstream init did not initialize line state");
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

#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
static void testHttp2PartialPrefaceNeedsMore(void)
{
    uint8_t  host[UINT8_MAX + 1U];
    uint32_t host_len = 0;

    const uint8_t partial_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n";
    require(routerHttp2SniffDomain(partial_preface,
                                   (uint32_t) sizeof(partial_preface) - 1U,
                                   host,
                                   (uint32_t) sizeof(host),
                                   &host_len) == kGenericSnifferNeedMore,
            "partial valid HTTP/2 preface did not ask for more bytes");
    require(host_len == 0 && host[0] == '\0', "partial HTTP/2 preface filled a host");
}

static void testHttp2MalformedPayloadFallsThrough(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x21;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.21", 443, IP_PROTO_TCP),
            "failed to set malformed HTTP/2 destination IP");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"h2.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp2};

    const uint8_t payload[] = "NOT HTTP/2\r\n\r\n";
    expectMatch("malformed HTTP/2 sniff falls through",
                classifyOneRule(&ts, &rule, line, payload, (uint32_t) sizeof(payload) - 1U),
                kRouterClassifyDefault,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "malformed HTTP/2 payload stored a domain");

    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testHttp2SniffingMatchesDestinationDomain(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x22;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.22", 443, IP_PROTO_TCP),
            "failed to set HTTP/2 destination IP");
    ip_addr_t original_ip = line->routing_context.dest_ctx.ip_address;

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"h2.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp2};

    uint8_t *request     = NULL;
    uint32_t request_len = makeHttp2PriorKnowledgeRequest(&request, "H2.Example.Test.:443");
    expectMatch("HTTP/2 sniffed authority route",
                classifyOneRule(&ts, &rule, line, request, request_len),
                kRouterClassifyTarget,
                target);

    address_context_t *dest = &line->routing_context.dest_ctx;
    requireDomain(dest, "H2.Example.Test");
    require(dest->type_ip == kCCTypeIp, "HTTP/2 sniffed domain changed destination type away from IP");
    require(ipAddrCmp(&dest->ip_address, &original_ip), "HTTP/2 sniffed domain changed destination IP");
    require(dest->port == 443, "HTTP/2 sniffed domain changed destination port");
    require(dest->proto_tcp, "HTTP/2 sniffed domain cleared destination TCP protocol");
    require(dest->domain_resolved, "IP-backed HTTP/2 sniffed domain was not marked resolved");

    free(request);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testHttp2SniffingSkippedOnUdpLines(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x23;

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.23", 443, IP_PROTO_UDP),
            "failed to set UDP destination IP for HTTP/2 sniffing test");

    router_rule_t   rule = parseDestinationDomainRule("{\"destination-domain\":\"udp-h2.example.test\"}", target);
    router_tstate_t ts   = {.sniffing_modes = kRouterSniffHttp2};

    uint8_t *request     = NULL;
    uint32_t request_len = makeHttp2PriorKnowledgeRequest(&request, "udp-h2.example.test");
    expectMatch("HTTP/2 sniff skipped on UDP",
                classifyOneRule(&ts, &rule, line, request, request_len),
                kRouterClassifyDefault,
                NULL);
    require(line->routing_context.dest_ctx.domain == NULL, "UDP HTTP/2 sniffing stored a domain");

    free(request);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}

static void testHttpAliasRoutesHttp1AndHttp2(void)
{
    tunnel_t *target = (tunnel_t *) (uintptr_t) 0x24;

    router_tstate_t ts   = {0};
    cJSON          *json = parseJsonObject("{\"sniffing\":[\"http\"]}");
    require(routerLoadSniffing(&ts, json), "http sniffing alias config failed");
    cJSON_Delete(json);
    require(ts.sniffing_modes == (kRouterSniffHttp1 | kRouterSniffHttp2),
            "http sniffing alias included an unexpected sniffing mode");

    router_rule_t rule = parseDestinationDomainRule("{\"destination-domain\":\"alias.example.test\"}", target);

    line_t *line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.24", 80, IP_PROTO_TCP),
            "failed to set HTTP alias HTTP/1 destination IP");
    const uint8_t request[] = "GET / HTTP/1.1\r\nHost: alias.example.test\r\n\r\n";
    expectMatch("http alias routed HTTP/1 Host",
                classifyOneRule(&ts, &rule, line, request, (uint32_t) sizeof(request) - 1U),
                kRouterClassifyTarget,
                target);
    requireDomain(&line->routing_context.dest_ctx, "alias.example.test");
    testLineDestroy(line);

    line = testLineCreate();
    require(addresscontextSetIpAddressPortProtocol(&line->routing_context.dest_ctx, "203.0.113.25", 443, IP_PROTO_TCP),
            "failed to set HTTP alias HTTP/2 destination IP");
    uint8_t *h2_request     = NULL;
    uint32_t h2_request_len = makeHttp2PriorKnowledgeRequest(&h2_request, "alias.example.test");
    expectMatch("http alias routed HTTP/2 authority",
                classifyOneRule(&ts, &rule, line, h2_request, h2_request_len),
                kRouterClassifyTarget,
                target);
    requireDomain(&line->routing_context.dest_ctx, "alias.example.test");

    free(h2_request);
    routerDestinationDomainDestroy(&rule);
    testLineDestroy(line);
}
#endif

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

    uint8_t too_large[kGenericSnifferMaxWindowBytes];
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

static void testAuthenticatedIdentityMatchesCredentialMarkers(void)
{
    line_t            *line = testLineCreate();
    router_match_ctx_t mctx = {.line = line};
    user_handle_t      vless_handle;

    router_rule_t username_rule = parseAuthenticatedIdentityRule("{\"username\":\"vless-user\"}");
    router_rule_t password_rule = parseAuthenticatedIdentityRule("{\"password\":\"trojan-password\"}");
    router_rule_t pair_rule =
        parseAuthenticatedIdentityRule("{\"username\":\"vless-user\",\"password\":\"vless-password\"}");
    router_rule_t crossed_rule =
        parseAuthenticatedIdentityRule("{\"username\":\"vless-user\",\"password\":\"trojan-password\"}");

    userHandleSet(&vless_handle, 7, 42);
    lineAddUser(line, &vless_handle, "vless-user", "vless-password");
    lineAddAuthenticatedCredentials(line, "trojan-user", "trojan-password");

    require(routerUsernameMatch(&username_rule, &mctx), "Router username did not match an older credential marker");
    require(routerPasswordMatch(&password_rule, &mctx), "Router password did not match the latest credential marker");
    require(routerUsernameMatch(&pair_rule, &mctx), "Router username/password pair did not match one marker");
    require(routerPasswordMatch(&pair_rule, &mctx), "Router password pair check did not match one marker");
    require(! routerUsernameMatch(&crossed_rule, &mctx),
            "Router username match crossed stacked credential markers");
    require(! routerPasswordMatch(&crossed_rule, &mctx),
            "Router password match crossed stacked credential markers");

    destroyAuthenticatedIdentityRule(&crossed_rule);
    destroyAuthenticatedIdentityRule(&pair_rule);
    destroyAuthenticatedIdentityRule(&password_rule);
    destroyAuthenticatedIdentityRule(&username_rule);
    testLineDestroy(line);
}

int main(void)
{
    testSniffingConfig();
#ifdef ROUTER_ENABLE_QUIC_SNIFFING
    testQuicSniffingRejectsNonQuicPayload();
    testQuicVectorFixtures();
    testQuicHttp3AliasRoutesVector();
    testQuicSniffingSkippedOnTcpVector();
    testQuicBadVectorFallsThrough();
#endif
    testProtocolConfig();
    testProtocolDescriptorTable();
    testPortMatchers();
    testRouterInitClearsOptionalFlags();
    testHttpSniffingMatchesDestinationDomain();
    testTlsSniffingMatchesDestinationDomain();
#ifdef ROUTER_ENABLE_HTTP2_SNIFFING
    testHttp2PartialPrefaceNeedsMore();
    testHttp2MalformedPayloadFallsThrough();
    testHttp2SniffingMatchesDestinationDomain();
    testHttp2SniffingSkippedOnUdpLines();
    testHttpAliasRoutesHttp1AndHttp2();
#endif
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
    testAuthenticatedIdentityMatchesCredentialMarkers();
    return 0;
}
