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
        f.node->fnInitU(f.node, f.line);
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
        f.node->fnPayloadU(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.upstream == 1, "first header delivery");
        buf = easyPayload(! splice && WW_HAVE_SPLICE);
        easyExpect(&f, buf, "prebody", 7, 3);
        f.node->fnPayloadU(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.upstream == 2, "header repeated on later/mixed delivery");
        buf = easyPayload(splice);
        easyExpect(&f, buf, "prebody", 7, 3);
        f.node->fnPayloadD(f.node, f.line, buf);
        easyRequire(f.expected == NULL && f.downstream == 1, "downstream passthrough");
        easyTeardown(&f);
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
    node_t node             = nodeHeaderClientGet();
    node.node_settings_json = cJSON_Parse(settings[2]);
    easy_fixture_t f;
    easySetup(&f, node.createHandle(&node));
    f.node->fnInitU(f.node, f.line);
    sbuf_t *buf = easyPayload(splice);
    easyWatch(buf);
    addresscontextSetIpAddress(lineGetSourceAddressContext(f.line), "192.0.2.1");
    fail_header = true;
    f.node->fnPayloadU(f.node, f.line, buf);
    fail_header = false;
    easyRequireDisposed();
    easyRequire(f.line == NULL && f.finishes == 2 && f.upstream == 0, "header failure cleanup");
    easyTeardown(&f);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
}
