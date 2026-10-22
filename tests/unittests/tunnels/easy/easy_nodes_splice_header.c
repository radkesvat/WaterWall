/*
 * Covers: easy nodes splice header; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Cases: one-time port/PROXY headers, TCP/UDP context snapshots across reentrant Init,
 * invalid transport flags, bypass and Finish with ordinary/splice buffers.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.easy_nodes_splice_unit
 */
#include "HeaderClient/interface.h"
#include "HeaderClient/structure.h"
#include "easy_nodes_splice_fixture.h"
#include <stdarg.h>

static bool fail_header;
int         __wrap_snprintf(char *output, size_t size, const char *format, ...);
int         __wrap_snprintf(char *output, size_t size, const char *format, ...)
{
    if (fail_header && strncmp(format, "PROXY ", 6) == 0)
        return -1;
    va_list args;
    va_start(args, format);
    int result = vsnprintf(output, size, format, args);
    va_end(args);
    return result;
}

/* Optimized glibc builds fortify snprintf; inject the same formatting failure there. */
int __wrap___snprintf_chk(char *output, size_t size, int flag, size_t object_size, const char *format, ...);
int __wrap___snprintf_chk(char *output, size_t size, int flag, size_t object_size, const char *format, ...)
{
    discard flag;
    discard object_size;
    if (fail_header && strncmp(format, "PROXY ", 6) == 0)
        return -1;
    va_list args;
    va_start(args, format);
    int result = vsnprintf(output, size, format, args);
    va_end(args);
    return result;
}

static easy_fixture_t *protocol_fixture;
static bool            protocol_reenter, protocol_splice;
static uint8_t         protocol_expected[8];
static unsigned        protocol_init_count;

static void headerRequireCleared(easy_fixture_t *f, line_t *l)
{
    const uint8_t *state = lineGetState(l, f->node);
    for (uint32_t i = 0; i < f->node->lstate_size; ++i)
        easyRequire(state[i] == 0, "HeaderClient retained protocol state");
}

/* A connector may rewrite either context and submit data synchronously in Init. */
static void headerProtocolNextInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++protocol_init_count;
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_TCP);
    if (protocol_reenter)
    {
        sbuf_t *buf = easyPayload(protocol_splice);
        easyExpect(protocol_fixture, buf, protocol_expected, sizeof(protocol_expected), 4);
        tunnelUpStreamPayload(protocol_fixture->node, l, buf);
    }
}

static void headerProtocolCloseDuringInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++protocol_init_count;
    tunnelDownStreamFin(protocol_fixture->node, l);
}

static void testHeaderProtocol(bool splice)
{
    const char *settings[] = {"{\"data\":\"src_context->protocol\"}",
                              "{\"data\":\"dest_context->protocol\"}",
                              "{\"data\":\"line->src_ctx->protocol\"}",
                              "{\"data\":\"line->dest_ctx->protocol\"}"};
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        for (unsigned reenter = 0; reenter < 2; ++reenter)
        {
            node_t node             = nodeHeaderClientGet();
            node.node_settings_json = cJSON_Parse(settings[mode]);
            easy_fixture_t f;
            easySetup(&f, node.createHandle(&node));
            easyRequire(f.node->lstate_size >= sizeof(headerclient_lstate_t), "protocol snapshot needs line storage");
            f.prev->chain_index = 0;
            f.node->chain_index = 1;
            f.next->chain_index = 2;
            addresscontextSetOnlyProtocol(lineGetSourceAddressContext(f.line), IP_PROTO_TCP);
            addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.line), IP_PROTO_UDP);
            protocol_fixture     = &f;
            protocol_reenter     = reenter;
            protocol_splice      = splice;
            protocol_init_count  = 0;
            protocol_expected[0] = mode % 2 == 0 ? 6 : 17;
            memoryCopy(protocol_expected + 1, "prebody", 7);
            f.next->fnInitU = headerProtocolNextInit;
            tunnelUpStreamInit(f.node, f.line);
            easyRequire(protocol_init_count == 1, "protocol mode did not initialize next");
            if (! reenter)
            {
                sbuf_t *buf = easyPayload(splice);
                easyExpect(&f, buf, protocol_expected, sizeof(protocol_expected), 4);
                tunnelUpStreamPayload(f.node, f.line, buf);
            }
            easyRequire(f.expected == NULL && f.upstream == 1, "protocol header was not the Init snapshot");
            easyRequire(! tunnelIsActiveForLine(f.node, f.line), "protocol HeaderClient did not bypass");
            headerRequireCleared(&f, f.line);
            sbuf_t *buf = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            tunnelUpStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.upstream == 2, "protocol header repeated");
            tunnelDownStreamFin(f.node, f.line);
            easyRequire(f.line == NULL && f.finishes == 1, "protocol bypass lost Finish");
            easyTeardown(&f);
            cJSON_Delete(node.node_settings_json);
            memoryFree(node.type);
        }
    }

    /* The selected context is authoritative: even valid flags in the other
     * context cannot rescue missing, ambiguous or unsupported selections. */
    const uint8_t invalid_flags[] = {0, 3, 4, 8, 5, 10, 15};
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        for (unsigned i = 0; i < sizeof(invalid_flags); ++i)
        {
            node_t node             = nodeHeaderClientGet();
            node.node_settings_json = cJSON_Parse(settings[mode]);
            easy_fixture_t f;
            easySetup(&f, node.createHandle(&node));
            addresscontextSetOnlyProtocol(lineGetSourceAddressContext(f.line), IP_PROTO_TCP);
            addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.line), IP_PROTO_UDP);
            address_context_t *selected =
                mode == 0 ? lineGetSourceAddressContext(f.line) : lineGetDestinationAddressContext(f.line);
            selected->proto_tcp    = (invalid_flags[i] & 1) != 0;
            selected->proto_udp    = (invalid_flags[i] & 2) != 0;
            selected->proto_icmp   = (invalid_flags[i] & 4) != 0;
            selected->proto_packet = (invalid_flags[i] & 8) != 0;
            protocol_fixture       = &f;
            protocol_init_count    = 0;
            f.next->fnInitU        = headerProtocolNextInit;
            line_t *observed       = f.line;
            lineRef(observed);
            tunnelUpStreamInit(f.node, f.line);
            easyRequire(f.line == NULL && ! lineIsAlive(observed) && f.finishes == 1 && protocol_init_count == 0 &&
                            f.upstream == 0,
                        "invalid protocol did not close only its initialized owner");
            headerRequireCleared(&f, observed);
            lineUnref(observed);
            easyTeardown(&f);
            cJSON_Delete(node.node_settings_json);
            memoryFree(node.type);
        }
    }

    /* Both Finish directions must release a captured marker even without data. */
    for (unsigned close = 0; close < 3; ++close)
    {
        node_t node             = nodeHeaderClientGet();
        node.node_settings_json = cJSON_Parse(settings[1]);
        easy_fixture_t f;
        easySetup(&f, node.createHandle(&node));
        addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.line), IP_PROTO_UDP);
        protocol_fixture    = &f;
        protocol_init_count = 0;
        if (close == 2)
            f.next->fnInitU = headerProtocolCloseDuringInit;
        line_t *observed = f.line;
        lineRef(observed);
        tunnelUpStreamInit(f.node, f.line);
        if (close == 0)
        {
            tunnelUpStreamFin(f.node, f.line);
            easyRequire(f.finishes == 1, "upstream protocol Finish changed direction");
            lineDestroy(f.line);
            f.line = NULL;
        }
        else if (close == 1)
            tunnelDownStreamFin(f.node, f.line);
        easyRequire(f.line == NULL && ! lineIsAlive(observed) && f.finishes == 1 && f.upstream == 0,
                    "protocol Finish before payload did not close cleanly");
        headerRequireCleared(&f, observed);
        lineUnref(observed);
        easyTeardown(&f);
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
    protocol_fixture = NULL;
}

void testHeaderSplice(bool splice)
{
    const char   *settings[] = {"{\"data\":4660}",
                                "{\"data\":\"src_context->port\"}",
                                "{\"data\":\"proxy-protocol-v1\",\"frontend-ipv4\":\"192.0.2.2\"}",
                                "{\"data\":\"proxy-protocol-v2\",\"frontend-ipv4\":\"192.0.2.2\"}"};
    const uint8_t v2[]       = {13, 10, 13,  10, 0, 13, 10,  81, 85, 73, 84,   10,   0x21, 0x11,
                                0,  12, 192, 0,  2, 1,  192, 0,  2,  2,  0x12, 0x34, 0,    80};
    const char    v1[]       = "PROXY TCP4 192.0.2.1 192.0.2.2 4660 80\r\n";
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        node_t node             = nodeHeaderClientGet();
        node.node_settings_json = cJSON_Parse(settings[mode]);
        easy_fixture_t f;
        easySetup(&f, node.createHandle(&node));
        addresscontextSetIpAddress(lineGetSourceAddressContext(f.line), "192.0.2.1");
        lineGetSourceAddressContext(f.line)->port          = 4660;
        lineGetRoutingContext(f.line)->peer_source_port    = 4660;
        lineGetRoutingContext(f.line)->local_listener_port = 80;
        f.prev->chain_index                                = 0;
        f.node->chain_index                                = 1;
        f.next->chain_index                                = 2;
        tunnelUpStreamInit(f.node, f.line);
        uint8_t  expected[160];
        uint32_t header = mode < 2 ? 2 : mode == 2 ? sizeof(v1) - 1 : sizeof(v2);
        if (mode < 2)
        {
            expected[0] = 0x12;
            expected[1] = 0x34;
        }
        else
            memcpy(expected, mode == 2 ? (const void *) v1 : (const void *) v2, header);
        memcpy(expected + header, "prebody", 7);
        sbuf_t *buf = easyPayload(splice);
        easyExpect(&f, buf, expected, header + 7, header + 3);
        tunnelUpStreamPayload(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.upstream == 1, "first header delivery");
        easyRequire(! tunnelIsActiveForLine(f.node, f.line), "HeaderClient stayed active after its header");
        const uint8_t *state = lineGetState(f.line, f.node);
        for (uint32_t i = 0; i < f.node->lstate_size; ++i)
            easyRequire(state[i] == 0, "HeaderClient retained state after bypass");
        buf = easyPayload(! splice && WW_HAVE_SPLICE);
        easyExpect(&f, buf, "prebody", 7, 3);
        tunnelUpStreamPayload(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.upstream == 2, "header repeated on later/mixed delivery");
        buf = easyPayload(splice);
        easyExpect(&f, buf, "prebody", 7, 3);
        tunnelDownStreamPayload(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.downstream == 1, "downstream passthrough");
        tunnelDownStreamFin(f.node, f.line);
        easyRequire(f.line == NULL && f.finishes == 1, "bypassed HeaderClient lost Finish");
        easyTeardown(&f);
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
    node_t node             = nodeHeaderClientGet();
    node.node_settings_json = cJSON_Parse(settings[2]);
    easy_fixture_t f;
    easySetup(&f, node.createHandle(&node));
    tunnelUpStreamInit(f.node, f.line);
    sbuf_t *buf = easyPayload(splice);
    easyWatch(buf);
    addresscontextSetIpAddress(lineGetSourceAddressContext(f.line), "192.0.2.1");
    fail_header = true;
    tunnelUpStreamPayload(f.node, f.line, buf);
    fail_header = false;
    easyRequireDisposed();
    easyRequire(f.line == NULL && f.finishes == 2 && f.upstream == 0, "header failure cleanup");
    easyTeardown(&f);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    testHeaderProtocol(splice);
}
