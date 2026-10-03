/*
 * SoftIpLimiter full-delivery identity materialization followed by opaque
 * bidirectional forwarding. Covers split VLESS/Trojan identity, passthrough,
 * malformed/rejected lines, nested input ordering and callback-driven teardown.
 * Real private pipes and worker-local pools; read counts exclude the receiving
 * byte oracle. Both variants compile the actual tunnel/helpers.
 * CTest: waterwall.softiplimiter_splice_unit; waterwall.softiplimiter_no_splice_unit
 */
#include "SoftIpLimiter/interface.h"
#include "SoftIpLimiter/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

#include <unistd.h>

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static line_t          *line;
static uint8_t          received[8192];
static size_t           received_length, materialized;
static unsigned         inits, payloads, finishes;
static bool             measuring, nested, close_init, close_payload, expect_down;
static sbuf_t          *expected_identity;

#if WW_HAVE_SPLICE
ssize_t __real_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes)
{
    ssize_t result = __real_read(fd, destination, bytes);
    if (measuring && result > 0)
        materialized += (size_t) result;
    return result;
}
#endif

static sbuf_t *input(const void *data, uint32_t length, bool splice, uint32_t prefix)
{
    sbuf_t *buf;
#if WW_HAVE_SPLICE
    if (splice)
    {
        buf = bufferpoolGetSpliceBuffer(env.pool);
        twfRequire(buf && prefix <= length, "allocate initial private pipe");
        uint32_t body = length - prefix;
        twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
                   "populate initial private pipe");
        buf->capacity = buf->l_pad + body;
        sbufSetLength(buf, body);
        sbufShiftLeft(buf, prefix);
        memoryCopy(sbufGetMutablePtr(buf), data, prefix);
        return buf;
    }
#else
    discard splice;
    discard prefix;
#endif
    buf = bufferpoolGetBestFit(env.pool, length, 256);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    return buf;
}

static void finish(tunnel_t *t, line_t *l)
{
    ++finishes;
    if (t == prev)
        lineDestroy(l);
}

static void init(tunnel_t *t, line_t *l)
{
    discard t;
    ++inits;
    if (close_init)
        node->fnFinD(node, l);
    else if (nested)
        node->fnPayloadU(node, l, input("B", 1, WW_HAVE_SPLICE, 0));
}

static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(t == (expect_down ? prev : next), "identity limiter changed callback direction");
    twfRequire(sbufGetLeftCapacity(buf) >= 128, "identity materialization lost onward padding");
    if (payloads == 0)
        twfRequire(! sbufIsSplice(buf), "initial identity replay was not ordinary");
    if (expected_identity)
        twfRequire(buf == expected_identity, "ready forwarding replaced a splice wrapper");
    uint32_t length = sbufGetLength(buf);
    twfRequire(length <= sizeof(received) - received_length, "identity capture overflow");
    bool saved = measuring;
    measuring  = false;
    sbufReadRangeToMemory(buf, received + received_length, length);
    measuring = saved;
    received_length += length;
    ++payloads;
    lineReuseBuffer(l, buf);
    if (nested && payloads == 1)
        node->fnPayloadU(node, l, input("C", 1, WW_HAVE_SPLICE, 0));
    if (close_payload)
        node->fnFinD(node, l);
}

static void setup(const char *identifier, bool reject)
{
    received_length = materialized = 0;
    inits = payloads = finishes = 0;
    measuring = nested = close_init = close_payload = expect_down = false;
    expected_identity                                             = NULL;
    twfWorkerEnvSetup(&env, 8192, 256);
    metadata = nodeSoftIpLimiterGet();
    char settings[224];
    snprintf(settings,
             sizeof(settings),
             "{\"identifier\":\"%s\",\"simultaneous-user-limit\":1,\"tolerance-ms\":60000,"
             "\"on-identification-failure\":\"%s\"}",
             identifier,
             reject ? "close" : "passthrough");
    metadata.node_settings_json = cJSON_Parse(settings);
    node                        = softiplimiterTunnelCreate(&metadata);
    prev                        = tunnelCreate(NULL, 0, 0);
    next                        = tunnelCreate(NULL, 0, 0);
    twfRequire(node && prev && next, "construct identity limiter fixture");
    prev->fnPayloadD = next->fnPayloadU = receive;
    prev->fnFinD = next->fnFinU = finish;
    next->fnInitU               = init;
    tunnelBind(prev, node);
    tunnelBind(node, next);
    twfLinePoolSetup(&lines, node->lstate_size, 4);
    line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    addresscontextSetIpAddress(lineGetSourceAddressContext(line), "192.0.2.1");
    node->fnInitU(node, line);
}

static void teardown(void)
{
    if (lineIsAlive(line))
    {
        node->fnFinU(node, line);
        lineDestroy(line);
    }
    twfRequireLineStateZeroed(line, node, "identity limiter retained parser/reentry state after close");
    twfRequire(twfLineRefCount(line) == 1, "identity limiter leaked a line reference");
    lineUnref(line);
    twfLinePoolTeardown(&lines);
    node->onDestroy(node, wwLifecycleStartupRollback());
    tunnelDestroy(prev);
    tunnelDestroy(next);
    cJSON_Delete(metadata.node_settings_json);
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

static void testIdentity(bool trojan, bool splice, bool fragmented, bool reentry)
{
    setup(trojan ? "trojan" : "vless", false);
    uint8_t vless[24] = {0};
    memorySet(vless + 1, 0x42, 16);
    memoryCopy(vless + 17, "payload", 7);
    const char  trojan_bytes[] = "0123456789abcdef0123456789abcdef0123456789abcdef01234567\r\npayload";
    const void *bytes          = trojan ? (const void *) trojan_bytes : vless;
    uint32_t    length         = trojan ? sizeof(trojan_bytes) - 1 : sizeof(vless);
    uint32_t    cut            = trojan ? 28 : 1;
    measuring                  = true;
    nested                     = reentry;
    if (fragmented)
    {
        node->fnPayloadU(node, line, input(bytes, cut, splice, 0));
        twfRequire(inits == 0 && payloads == 0, "partial identity initialized next prematurely");
        node->fnPayloadU(node, line, input((const uint8_t *) bytes + cut, length - cut, splice, 4));
    }
    else
        node->fnPayloadU(node, line, input(bytes, length, splice, 4));
    twfRequire(inits == 1 && received_length == length + (reentry ? 2 : 0), "identity replay changed length/order");
    twfRequire(memoryCompare(received, bytes, length) == 0, "identity replay changed wire bytes");
    if (reentry)
        twfRequire(memoryCompare(received + length, "BC", 2) == 0, "nested pipe input overtook initial replay");
    twfRequire(materialized == (splice ? length - 4 : 0), "early materialization did not consume full deliveries");
    twfRequire(((softiplimiter_lstate_t *) lineGetState(line, node))->phase == kSoftIpLimiterPhaseEstablished,
               "recognized identity was not admitted");
    materialized = 0;
    for (unsigned down = 0; down < 2; ++down)
    {
        expect_down       = down;
        sbuf_t *buf       = input("opaque bytes", 12, splice, 2);
        expected_identity = buf;
        if (down)
            node->fnPayloadD(node, line, buf);
        else
            node->fnPayloadU(node, line, buf);
        expected_identity = NULL;
    }
    twfRequire(materialized == 0, "ready identity limiter materialized opaque input");
    teardown();
}

static void testPassthrough(bool splice)
{
    setup("vless", false);
    node->fnPayloadU(node, line, input("invalid protocol", 16, splice, 1));
    twfRequire(inits == 1 && received_length == 16 && memoryCompare(received, "invalid protocol", 16) == 0,
               "passthrough changed invalid initial wire bytes");
    twfRequire(((softiplimiter_lstate_t *) lineGetState(line, node))->phase == kSoftIpLimiterPhasePassthrough,
               "invalid identity did not select passthrough");
    for (unsigned down = 0; down < 2; ++down)
    {
        expect_down       = down;
        sbuf_t *buf       = input("tail", 4, splice, 0);
        expected_identity = buf;
        if (down)
            node->fnPayloadD(node, line, buf);
        else
            node->fnPayloadU(node, line, buf);
        expected_identity = NULL;
    }
    teardown();
}

static void testClose(bool splice, unsigned kind)
{
    setup("vless", true);
    uint8_t bytes[24] = {0};
    memorySet(bytes + 1, 0x42, 16);
    if (kind == 0)
        bytes[0] = 1;
    else if (kind == 1)
        addresscontextReset(lineGetSourceAddressContext(line));
    else if (kind == 2)
        close_init = true;
    else
        close_payload = true;
    node->fnPayloadU(node, line, input(bytes, sizeof(bytes), splice, 1));
    twfRequire(! lineIsAlive(line), "identity rejection/reentrant close left connection alive");
    twfRequire(payloads == (kind == 3), "identity limiter sent data after rejection/Init close");
    teardown();
}

int main(void)
{
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        for (unsigned trojan = 0; trojan < 2; ++trojan)
        {
            testIdentity(trojan, splice, false, false);
            testIdentity(trojan, splice, true, false);
            testIdentity(trojan, splice, true, true);
        }
        testPassthrough(splice);
        for (unsigned kind = 0; kind < 4; ++kind)
            testClose(splice, kind);
    }
    metadata = nodeSoftIpLimiterGet();
    twfRequire(metadata.flags & kNodeFlagSupportsSplice, "SoftIpLimiter lacks splice capability");
    memoryFree(metadata.type);
    puts("SoftIpLimiter early materialization and opaque splice forwarding passed");
    return 0;
}
