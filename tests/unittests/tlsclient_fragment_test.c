#include "StreamFragmenter/structure.h"
#include "TlsClient/structure.h"
#include "tunnel_line_failure_harness.h"
#include "wloop_internal.h"

static twf_worker_env_t env;
static node_t           tls_node, backend_node, helper_node;
static tunnel_t        *tls, *previous, *backend, *transport_helper;
static tunnel_chain_t  *chain;
static line_t          *line;
static unsigned         child_count, writes, next_inits, next_finishes, prev_est;
static bool             refuse_child, refuse_ssl, close_at_est, close_at_payload;
static uint8_t          wire[65536];
static size_t           wire_size;
static uint32_t         lengths[8];

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash);
node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash)
{
    discard config;
    twfRequire(hash == backend_node.hash_name, "helper lost the configured next link");
    return &backend_node;
}

static void childDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    twfRequire(child_count == 1, "child destroyed twice");
    --child_count;
    tunnelDefaultOnDestroy(t, context);
}
tunnel_t *__real_nodemanagerCreateTunnelInstance(node_t *node);
tunnel_t *__wrap_nodemanagerCreateTunnelInstance(node_t *node);
tunnel_t *__wrap_nodemanagerCreateTunnelInstance(node_t *node)
{
    if (refuse_child)
        return NULL;
    tunnel_t *child = __real_nodemanagerCreateTunnelInstance(node);
    if (child != NULL)
    {
        ++child_count;
        child->onDestroy = childDestroy;
    }
    return child;
}
SSL_CTX *__real_WW_BSSL_SSL_CTX_new(const SSL_METHOD *method);
SSL_CTX *__wrap_WW_BSSL_SSL_CTX_new(const SSL_METHOD *method);
SSL_CTX *__wrap_WW_BSSL_SSL_CTX_new(const SSL_METHOD *method)
{
    return refuse_ssl ? NULL : __real_WW_BSSL_SSL_CTX_new(method);
}

static tunnel_t *create(const char *settings)
{
    tls_node                    = nodeTlsClientGet();
    tls_node.name               = (char *) "tls";
    tls_node.next               = (char *) "out";
    tls_node.hash_next          = 17;
    tls_node.node_settings_json = cJSON_Parse(settings);
    twfRequire(tls_node.node_settings_json != NULL, "fixture JSON");
    tunnel_t *result = tlsclientTunnelCreate(&tls_node);
    /* The private helper must own its settings independently. */
    cJSON_Delete(tls_node.node_settings_json);
    tls_node.node_settings_json = NULL;
    return result;
}
static void destroy(tunnel_t *t)
{
    if (t != NULL)
        t->onDestroy(t, wwLifecycleStartupRollback());
    memoryFree(tls_node.type);
    twfRequire(child_count == 0, "owned fragment helper leaked");
}
static void sourceFinish(void)
{
    tls->fnFinU(tls, line);
    twfRequire(lineIsAlive(line), "TlsClient/helper destroyed borrowed line");
    lineDestroy(line);
}
static void previousFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static void previousSignal(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void previousEst(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == line, "Est changed line identity");
    ++prev_est;
    if (close_at_est)
        sourceFinish();
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++next_inits;
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++next_finishes;
}
static void nextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint32_t n = sbufGetLength(buf);
    twfRequire(l == line && writes < ARRAY_SIZE(lengths) && n <= sizeof(wire) - wire_size, "wire capture bound");
    twfRequire(sbufGetLeftCapacity(buf) >= 64 && ! sbufIsSplice(buf), "TLS fragment padding/representation");
    lengths[writes++] = n;
    memoryCopy(wire + wire_size, sbufGetRawPtr(buf), n);
    wire_size += n;
    lineReuseBuffer(l, buf);
    if (close_at_payload)
        sourceFinish();
}
static void insertTransportHelper(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnelBind(t->prev, transport_helper);
    tunnelBind(transport_helper, t);
    tunnelchainInsert(tc, transport_helper);
    tunnelchainInsert(tc, t);
}
static void openLine(const char *settings)
{
    writes = next_inits = next_finishes = prev_est = 0;
    wire_size                                      = 0;
    tls                                            = create(settings);
    twfRequire(tls != NULL, "valid fragment settings rejected");
    tlsclient_tstate_t *ts = tunnelGetState(tls);
    twfRequire(ts->fragment_tunnel != NULL, "fragment helper missing");
    backend_node = (node_t) {
        .name = (char *) "out", .type = (char *) "backend", .hash_name = 17, .flags = kNodeFlagSupportsSplice};
    helper_node =
        (node_t) {.type = (char *) "transport-helper", .flags = kNodeFlagSupportsSplice, .required_padding_left = 64};
    previous              = tunnelCreate(NULL, 0, 0);
    previous->fnFinD      = previousFinish;
    previous->fnEstD      = previousEst;
    previous->fnPauseD    = previousSignal;
    previous->fnResumeD   = previousSignal;
    backend               = tunnelCreate(&backend_node, 0, 0);
    backend_node.instance = backend;
    backend->onChain      = insertTransportHelper;
    backend->fnInitU      = nextInit;
    backend->fnPayloadU   = nextPayload;
    backend->fnFinU       = nextFinish;
    transport_helper      = tunnelCreate(&helper_node, 0, 0);
    tunnelBind(previous, tls);
    chain                        = tunnelchainCreate(1);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    tls->onChain(tls, chain);
    twfRequire(! startupFailurePending() && chain->tunnels.len == 4, "expanded chain construction");
    twfRequire(wwStartupSucceeded(wwStartupContextEnd(&startup)), "chain startup failed");
    twfRequire(tls->next == ts->fragment_tunnel && tls->next->next == transport_helper &&
                   transport_helper->next == backend && tunnelGetBranchEntry(previous, tls) == tls,
               "fragment or branch entry order");
    uint32_t offset = 0;
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
        chain->tunnels.tuns[i]->onIndex(chain->tunnels.tuns[i], i, &offset);
    tunnelchainFinalize(chain);
    twfRequire(! chain->supports_splice && chain->sum_padding_left == 64, "TLS splice block/padding changed");
    line = lineCreate(chain->line_pools, 0);
    lineRef(line);
    tls->fnInitU(tls, line);
    twfRequire(next_inits == 1, "transport Init count");
}
static void closeLine(void)
{
    if (lineIsAlive(line))
        sourceFinish();
    lineUnref(line);
    twfRequire(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0 && env.loop->ntimers == 0, "line/timer leak");
    destroy(tls);
    tunnelDestroy(previous);
    tunnelDestroy(transport_helper);
    tunnelDestroy(backend);
    tunnelchainDestroy(chain);
    close_at_est = close_at_payload = false;
    twfRequireNoLeakedBuffers();
}

int main(void)
{
    twfWorkerEnvSetup(&env, 32768, 64);
    buffer_pool_t *pool_slots[2] = {env.pool, env.pool};
    GSTATE.shortcut_buffer_pools = pool_slots;
    const char *prefix           = "{\"sni\":\"tls.integration.test\",\"verify\":false";
    char        json[1024];
    const char *bad[] = {"null",
                         "false",
                         "[]",
                         "1",
                         "{}",
                         "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[0,0,100]]}",
                         "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"wait-for-est\":null}",
                         "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"tls-hello-fragment\":1}",
                         "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"tls-hello-timeout-ms\":1000}",
                         "{},\"fragment\":{}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        stringNPrintf(json, sizeof(json), "%s,\"fragment\":%s}", prefix, bad[i]);
        twfRequire(create(json) == NULL, "invalid fragment accepted");
        destroy(NULL);
    }
    stringNPrintf(json, sizeof(json), "%s}", prefix);
    tls = create(json);
    twfRequire(tls != NULL && tls->onChain == tunnelDefaultOnChain &&
                   ((tlsclient_tstate_t *) tunnelGetState(tls))->fragment_tunnel == NULL,
               "omission changed topology");
    destroy(tls);

    stringNPrintf(json,
                  sizeof(json),
                  "%s,\"fragment\":{\"mode\":\"counter\",\"count\":1,\"cuts\":[[250,0,100],[300,0,100]]}}",
                  prefix);
    refuse_child = true;
    twfRequire(create(json) == NULL, "child construction refusal");
    destroy(NULL);
    refuse_child = false;
    refuse_ssl   = true;
    twfRequire(create(json) == NULL, "SSL construction refusal");
    destroy(NULL);
    refuse_ssl = false;

    openLine(json);
    tunnel_t                  *fragment = tls->next;
    streamfragmenter_lstate_t *fs       = lineGetState(line, fragment);
    twfRequire(! writes && fs->head != NULL && ! fs->timer, "ClientHello escaped before Est");
    uint8_t        expected[65536];
    const uint32_t expected_size = sbufGetLength(fs->head->buf);
    twfRequire(expected_size > 300 && expected_size <= sizeof(expected), "ClientHello capture size");
    memoryCopy(expected, sbufGetRawPtr(fs->head->buf), expected_size);
    tunnelPrevDownStreamPause(backend, line);
    tunnelPrevDownStreamEst(backend, line);
    twfRequire(prev_est == 1 && ! writes, "Est was delayed by Pause or output bypassed it");
    tunnelPrevDownStreamResume(backend, line);
    twfRequire(writes == 3 && lengths[0] == 250 && lengths[1] == 50 && wire_size == expected_size &&
                   memoryCompare(wire, expected, expected_size) == 0,
               "fragmented ClientHello bytes changed");
    closeLine();

    stringNPrintf(json,
                  sizeof(json),
                  "%s,\"fragment\":{\"mode\":\"counter\",\"count\":1,\"tls-hello-fragment\":true,"
                  "\"tls-hello-timeout-ms\":1000,\"cuts\":[[250,0,100],[300,0,100]]}}",
                  prefix);
    openLine(json);
    fragment                                     = tls->next;
    fs                                           = lineGetState(line, fragment);
    streamfragmenter_tstate_t *fragment_settings = tunnelGetState(fragment);
    twfRequire(fragment_settings->tls_hello_fragment && fragment_settings->tls_hello_timeout_ms == 1000 &&
                   fs->head != NULL && fs->head->kind == kStreamFragmenterJobHello && ! fs->timer,
               "TlsClient nested TLS hello settings or collection");
    tunnelPrevDownStreamEst(backend, line);
    twfRequire(writes == 3 && lengths[0] == 255 && lengths[1] == 55 && wire_size > 310,
               "nested TLS record cut endpoints");
    uint32_t offset = 0, handshake_size = 0;
    for (unsigned i = 0; i < 3; ++i)
    {
        twfRequire(offset + 5 <= wire_size && wire[offset] == 22 && wire[offset + 1] == 3 && wire[offset + 2] >= 1 &&
                       wire[offset + 2] <= 3,
                   "nested rewritten TLS record header");
        const uint32_t record_size = ((uint32_t) wire[offset + 3] << 8) | wire[offset + 4];
        twfRequire(record_size > 0 && record_size <= 16384 && offset + 5 + record_size <= wire_size,
                   "nested rewritten TLS record length");
        handshake_size += record_size;
        offset += record_size + 5;
    }
    const uint32_t declared_hello = 4 + ((uint32_t) wire[6] << 16) + ((uint32_t) wire[7] << 8) + wire[8];
    twfRequire(wire[5] == 1 && handshake_size == declared_hello && handshake_size > 300 && offset <= wire_size,
               "nested ClientHello framing incomplete");
    closeLine();

    for (unsigned event = 0; event < 3; ++event)
    {
        openLine(json);
        close_at_est     = event == 0;
        close_at_payload = event == 1;
        if (event < 2)
            tunnelPrevDownStreamEst(backend, line);
        else
            tunnelPrevDownStreamFinish(backend, line);
        twfRequire(! lineIsAlive(line) && writes == (event == 1 ? 1U : 0U) && next_finishes == (event == 2 ? 0U : 1U),
                   "reentrant close continued/reflected");
        closeLine();
    }
    stringNPrintf(json,
                  sizeof(json),
                  "%s,\"fragment\":{\"mode\":\"counter\",\"count\":1,\"cuts\":[[250,0,100]],\"wait-for-est\":false}}",
                  prefix);
    openLine(json);
    twfRequire(writes == 2 && ! prev_est, "explicit false was ignored");
    closeLine();
    stringNPrintf(
        json, sizeof(json), "%s,\"fragment\":{\"mode\":\"counter\",\"count\":1,\"cuts\":[[250,60000,100]]}}", prefix);
    openLine(json);
    tunnelPrevDownStreamEst(backend, line);
    fs = lineGetState(line, tls->next);
    twfRequire(fs->timer != NULL && ! writes, "delayed fragment missing");
    wtimerTestMakePendingOneShot(fs->timer);
    closeLine();
    twfWorkerEnvTeardown(&env);
    puts("tlsclient_fragment: passed");
    return 0;
}
