#include "AuthenticationClient/structure.h"
#include "HttpProxyServer/structure.h"

/* Real pool-backed lines and callbacks, with no sockets or linker wrapping. */
static tunnel_t *proxy, *prev, *next;
static line_t   *client, *child;
static unsigned  opens, closes, establishments, client_writes, request_writes;
static unsigned  close_on; /* 1 Init, 2 Est, 3 Payload, 4 Pause, 5 Resume */
static bool      refuse, automatic_response;
static char      received[262144], sent[131072];
static size_t    received_len;
static size_t    sent_len;
static bool      producer_paused[2];

static void require(bool ok, const char *text)
{
    if (! ok)
    {
        fprintf(stderr, "proxy lifetime: %s\n", text);
        exit(1);
    }
}

static void clientClose(void)
{
    if (! lineIsAlive(client))
        return;
    httpproxyserverTunnelUpStreamFinish(proxy, client);
    require(lineIsAlive(client), "proxy destroyed borrowed client");
    lineDestroy(client);
}

static void previousFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == client, "callback used child as client");
    lineDestroy(l);
}

static void previousEst(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == client, "Est identity");
    ++establishments;
    if (close_on == 2)
        clientClose();
}

static void previousPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    require(l == client, "Payload identity");
    size_t n = sbufGetLength(b);
    require(n < sizeof(received) - received_len, "test output capacity");
    memoryCopy(received + received_len, sbufGetRawPtr(b), n);
    received_len += n;
    received[received_len] = 0;
    ++client_writes;
    lineReuseBuffer(l, b);
    if (close_on == 3)
        clientClose();
}

static void childPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[1] = true;
}

static void childResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[1] = false;
}

static void previousPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[0] = true;
    if (close_on == 4)
        clientClose();
}

static void previousResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    producer_paused[0] = false;
    if (close_on == 5)
        clientClose();
}

static void childFinish(tunnel_t *t, line_t *l)
{
    discard t;
    require(l == child, "wrong child finished");
    ++closes;
    child = NULL;
}

static void childInit(tunnel_t *t, line_t *l)
{
    discard t;
    child = l;
    ++opens;
    require(lineGetRoutingContext(l)->local_listener_port == 8080, "listener metadata");
    require(lineGetRoutingContext(l)->peer_source_port == 54321, "peer metadata");
    require(lineGetSourceAddressContext(l)->proto_tcp, "source protocol");
    require(ip_addr_cmp(&lineGetSourceAddressContext(l)->ip_address, &lineGetSourceAddressContext(client)->ip_address),
            "source IP");
    if (close_on == 1)
        clientClose();
    else if (refuse)
    {
        lineRef(l);
        httpproxyserverTunnelDownStreamFinish(proxy, l);
        require(! lineIsAlive(l), "owner Finish left child alive");
        lineUnref(l);
        child = NULL;
    }
    else
        httpproxyserverTunnelDownStreamEst(proxy, l);
}

static void sendBytes(line_t *l, bool downstream, const char *bytes)
{
    size_t  n = stringLength(bytes);
    sbuf_t *b = bufferpoolGetBestFit(lineGetBufferPool(l), (uint32_t) n, 64);
    memoryCopy(sbufGetMutablePtr(b), bytes, n);
    sbufSetLength(b, (uint32_t) n);
    if (downstream)
        httpproxyserverTunnelDownStreamPayload(proxy, l, b);
    else
        httpproxyserverTunnelUpStreamPayload(proxy, l, b);
}

static void childPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    require(l == child, "request did not use owned child");
    require(sbufGetLeftCapacity(b) >= 64, "rewritten buffer lost chain padding");
    size_t n = sbufGetLength(b);
    require(n < sizeof(sent) - sent_len, "test request capacity");
    memoryCopy(sent + sent_len, sbufGetRawPtr(b), n);
    sent_len += n;
    sent[sent_len] = 0;
    ++request_writes;
    lineReuseBuffer(l, b);
    if (automatic_response)
        sendBytes(l, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
}

static void resetClient(tunnel_chain_t *chain)
{
    opens = closes = establishments = client_writes = request_writes = 0;
    received_len                                                     = 0;
    sent_len                                                         = 0;
    sent[0]                                                          = 0;
    producer_paused[0] = producer_paused[1] = false;
    received[0]                             = 0;
    close_on                                = 0;
    refuse                                  = false;
    automatic_response                      = true;
    child                                   = NULL;
    client                                  = lineCreateForWorker(0, chain->line_pools, 0);
    lineRef(client); /* test observation reference */
    lineGetRoutingContext(client)->local_listener_port = 8080;
    lineGetRoutingContext(client)->peer_source_port    = 54321;
    require(addresscontextSetIpAddress(lineGetSourceAddressContext(client), "127.0.0.2"), "source address");
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(client), IP_PROTO_TCP);
    httpproxyserverTunnelUpStreamInit(proxy, client);
}

static void childEof(void)
{
    line_t *l = child;
    child     = NULL;
    lineRef(l);
    httpproxyserverTunnelDownStreamFinish(proxy, l);
    require(! lineIsAlive(l), "EOF left owned child alive");
    lineUnref(l);
}

static void pipelinePressure(tunnel_chain_t *chain, const char *get)
{
    hps_tstate_t *ts    = tunnelGetState(proxy);
    uint32_t      saved = ts->max_pending;
    ts->max_pending     = 65536;
    resetClient(chain);
    automatic_response = false;
    char pipeline[51000];
    int  prefix = stringNPrintf(pipeline,
                               sizeof(pipeline),
                               "%sPOST http://127.0.0.1:80/second HTTP/1.1\r\nHost: a\r\nContent-Length: 50000\r\n\r\n",
                               get);
    memorySet(pipeline + prefix, 'p', 50000);
    pipeline[prefix + 50000] = 0;
    sendBytes(client, false, pipeline); /* One already admitted callback may cross the high watermark. */
    require(producer_paused[0] && ! strstr(sent, "POST"), "R1 pipeline admission or sequencing");
    require(! producer_paused[1], "R1 queued request paused current response producer");
    char response[100100];
    int  header = stringNPrintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
    memorySet(response + header, 'r', 100000);
    response[header + 100000] = 0;
    sendBytes(child, true, response); /* Several capacity-limited slices in one permitted callback. */
    require(lineIsAlive(client) && received_len == (size_t) header + stringLength("Via: 1.1 WaterWall\r\n") + 100000,
            "R1 large response did not stream"); /* rewrite appends Via: 1.1 WaterWall */
    require(opens == 1 && strstr(sent, "POST /second HTTP/1.1") && ! producer_paused[0], "R1 pipeline did not resume");
    const char *post = strstr(sent, "POST /second");
    const char *body = strstr(post, "\r\n\r\n") + 4;
    require(stringLength(body) == 50000 && strspn(body, "p") == 50000, "R1 POST bytes changed or replayed");
    require(! producer_paused[1], "R1 response producer remained paused");
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    require(strstr(received + received_len - 4, "ok") != NULL, "R1 second response missing");
    clientClose();
    lineUnref(client);

    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    char overflow[70001];
    memorySet(overflow, 'x', sizeof(overflow) - 1);
    overflow[sizeof(overflow) - 1] = 0;
    sendBytes(client, false, overflow); /* Bounded tolerance for an already in-flight callback. */
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(! lineIsAlive(client) && child == NULL, "R1 real overflow did not settle");
    lineUnref(client);
    ts->max_pending = saved;
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "R1 line leak");
}

static void responseEof(tunnel_chain_t *chain, const char *get)
{
    const char *truncated[] = {"HTTP/1.1 20",
                               "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r",
                               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: partial",
                               "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx"};
    for (size_t i = 0; i < ARRAY_SIZE(truncated); ++i)
    {
        resetClient(chain);
        automatic_response = false;
        sendBytes(client, false, get);
        sendBytes(child, true, truncated[i]);
        size_t before = received_len;
        childEof();
        require(! lineIsAlive(client), "R3 truncation did not settle directly at EOF");
        require(i < 2 ? strstr(received, "502 Bad Gateway") != NULL : received_len == before,
                "R3 wrong commitment handling");
        require(closes == 0, "R3 reflected Finish toward child");
        lineUnref(client);
    }
    const char *complete[] = {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                              "HTTP/1.1 200 OK\r\n\r\nok"};
    for (size_t i = 0; i < ARRAY_SIZE(complete); ++i)
    {
        resetClient(chain);
        automatic_response = false;
        sendBytes(client, false, get);
        /* EOF must preserve already in-flight input retained behind a blocked consumer. */
        httpproxyserverTunnelUpStreamPause(proxy, client);
        sendBytes(child, true, complete[i]); /* already in-flight input */
        childEof();
        require(lineIsAlive(client) && received_len == 0, "R3 discarded paused complete response at EOF");
        httpproxyserverTunnelUpStreamResume(proxy, client);
        require(strstr(received, i == 1 ? "2\r\nok\r\n0\r\n\r\n" : "\r\n\r\nok") != NULL && ! strstr(received, "502"),
                "R3 valid retained response lost on Resume");
        if (i < 2)
        {
            require(lineIsAlive(client), "R3 complete persistent response killed client");
            sendBytes(client, false, get);
            require(opens == 2, "R3 complete EOF prevented replacement");
            clientClose();
        }
        else
            require(! lineIsAlive(client), "R3 close-delimited response did not close");
        lineUnref(client);
    }
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "R3 line leak");
}

static tunnel_t *localConfig(const char *json, bool valid)
{
    node_t node = {.type               = (char *) "HttpProxyServer",
                   .next               = (char *) "out",
                   .hash_next          = 1,
                   .node_settings_json = cJSON_Parse(json)};
    require(node.node_settings_json != NULL, "test JSON");
    tunnel_t *t = httpproxyserverTunnelCreate(&node);
    require((t != NULL) == valid, "L1 local configuration acceptance");
    cJSON_Delete(node.node_settings_json);
    if (t)
    {
        t->node          = NULL; /* No runtime callback below needs the temporary configuration node. */
        hps_tstate_t *ts = tunnelGetState(t);
        require(ts->auth_mode == kHpsAuthLocal && ! ts->controller && ! ts->auth_node && ! ts->auth,
                "L4 local configuration created tracked topology");
        httpproxyserverTunnelOnPrepair(t);
    }
    return t;
}

static void localConfiguration(void)
{
    const char *bad[] = {
        "{}",
        "{\"users\":null}",
        "{\"users\":[]}",
        "{\"users\":{}}",
        "{\"users\":true}",
        "{\"no-auth\":true,\"users\":null}",
        "{\"users\":[],\"auth-client-node-name\":null}",
        "{\"users\":[null]}",
        "{\"users\":[\"u:p\"]}",
        "{\"users\":[{}]}",
        "{\"users\":[{\"username\":\"u\"}]}",
        "{\"users\":[{\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":1,\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":null}]}",
        "{\"users\":[{\"username\":\"\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"\"}]}",
        "{\"users\":[{\"username\":\"u:p\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\\n\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\\u007f\"}]}",
        "{\"users\":[{\"username\":\"u\",\"username\":\"v\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"password\":\"q\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"limit\":0}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"enabled\":true}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\",\"expire-at-ms\":0}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\"},{\"username\":\"u\",\"password\":\"p\"}]}",
        "{\"users\":[{\"username\":\"u\",\"password\":\"p\"},{}]}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
        localConfig(bad[i], false);
    tunnel_t     *t  = localConfig("{\"no-auth\":false,\"users\":[{\"username\":\"u\",\"password\":\"p:q\"},"
                                   "{\"username\":\"u\",\"password\":\"p\"},{\"username\":\"v\",\"password\":\"p\"}]}",
                              true);
    hps_tstate_t *ts = tunnelGetState(t);
    require(ts->user_count == 3 && ! stringCompare(ts->users[0].password, "p:q"), "L1 owned credential copy");
    httpproxyserverTunnelDestroy(t, NULL);
    char component[257], json[1024];
    memorySet(component, 'x', 255);
    component[255] = 0;
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"%s\",\"password\":\"%s\"}]}", component, component);
    t = localConfig(json, true);
    httpproxyserverTunnelDestroy(t, NULL);
    component[255] = 'x';
    component[256] = 0;
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"%s\",\"password\":\"p\"}]}", component);
    localConfig(json, false);
    stringNPrintf(json, sizeof(json), "{\"users\":[{\"username\":\"u\",\"password\":\"%s\"}]}", component);
    localConfig(json, false);
}

static void localAuthentication(tunnel_chain_t *chain)
{
    tunnel_t *saved = proxy;
    proxy           = localConfig("{\"users\":[{\"username\":\"alice\",\"password\":\"one\"},"
                                  "{\"username\":\"bob\",\"password\":\"two\"}]}",
                        true);
    proxy->chain    = chain;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
    const char *alice = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic "
                        "YWxpY2U6b25l\r\nAuthorization: Bearer origin\r\n\r\n";
    const char *bob =
        "GET http://127.0.0.1:80/b HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic Ym9iOnR3bw==\r\n\r\n";
    resetClient(chain);
    user_handle_t inherited = {.generation = 1, .user_id = 42};
    lineAddUser(client, &inherited, "inherited", "value");
    for (unsigned i = 0; i < 8; ++i)
        sendBytes(client, false, alice);
    require(opens == 1 && lineGetUserAuthCount(child) == 2 && lineGetUserAuthCount(client) == 1,
            "L3 local reuse or marker growth");
    require(lineGetUserAuthAt(child, 0)->has_handle && ! lineGetUserAuthAt(child, 1)->has_handle &&
                lineHasAuthenticatedCredentials(child, "alice", "one") &&
                lineHasAuthenticatedCredentials(child, "inherited", "value"),
            "L4 credentials-only marker/inheritance");
    require(! strstr(sent, "Proxy-Authorization") && strstr(sent, "Authorization: Bearer origin"),
            "L2 header stripping");
    sendBytes(client, false, bob);
    require(opens == 2 && closes == 1 && lineHasAuthenticatedCredentials(child, "bob", "two"),
            "L3 pair switch metadata");
    sendBytes(client, false, "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && opens == 2 && strstr(received, "407"), "L3 missing reauthentication");
    lineUnref(client);
    resetClient(chain);
    for (unsigned i = 0; i < kLineMaxUsers; ++i)
        lineAddUser(client, &inherited, NULL, NULL);
    sendBytes(client, false, alice);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "L4 local marker capacity");
    lineUnref(client);
    for (unsigned event = 1; event <= 5; ++event)
    {
        resetClient(chain);
        close_on = event;
        sendBytes(client, false, alice);
        if (event >= 4)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            if (event == 5)
                httpproxyserverTunnelDownStreamResume(proxy, child);
        }
        require(! lineIsAlive(client) && child == NULL && closes == 1, "L5 local reentrant settlement");
        lineUnref(client);
    }
    resetClient(chain);
    sendBytes(client, false, alice);
    httpproxyserverTunnelOnWorkerQuiesce(proxy, 0, NULL);
    httpproxyserverTunnelOnWorkerStop(proxy, 0, NULL);
    require(child == NULL && lineIsAlive(client), "L5 local child drain");
    clientClose();
    lineUnref(client);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "L5 local reference leak");
    httpproxyserverTunnelDestroy(proxy, NULL);
    proxy = saved;
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
}

int main(void)
{
    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    master_pool_t *large = masterpoolCreateWithCapacity(8), *small = masterpoolCreateWithCapacity(8);
    master_pool_t *ios  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large, small, 4, 16384, 1024);
    bufferpoolUpdateAllocationPaddings(pool, 64, 64);
    threadsafe_generic_pool_t *io_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(ios, sizeof(wio_t), 8);
    GSTATE.shortcut_buffer_pools = &pool;
    GSTATE.shortcut_wios_pools   = &io_pool;
    wloop_t *loop                = wloopCreate(WLOOP_FLAG_AUTO_FREE, pool, 0);
    GSTATE.shortcut_loops        = &loop;
    worker_t worker = {.wid = 0, .buffer_pool = pool, .wios_pool = io_pool, .loop = loop, .has_event_loop = true};
    GSTATE.workers  = &worker;
    testWorkerBindWID(0);
    localConfiguration();
    node_t local_node = {
        .type               = (char *) "HttpProxyServer",
        .next               = (char *) "out",
        .hash_next          = 1,
        .node_settings_json = cJSON_Parse(
            "{\"users\":[{\"username\":\"alice\",\"password\":\"one\"},{\"username\":\"bob\",\"password\":\"two\"}]}")};
    tunnel_t *local_proxy = httpproxyserverTunnelCreate(&local_node);
    require(local_proxy != NULL, "L1 local users require no account service");
    httpproxyserverTunnelDestroy(local_proxy, NULL);
    cJSON_Delete(local_node.node_settings_json);
    node_t node = {.type               = (char *) "HttpProxyServer",
                   .next               = (char *) "out",
                   .hash_next          = 1,
                   .node_settings_json = cJSON_Parse("{\"no-auth\":true}")};
    proxy       = httpproxyserverTunnelCreate(&node);
    require(proxy != NULL, "create");
    prev = tunnelCreate(NULL, 0, 0);
    next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, proxy);
    tunnelBind(proxy, next);
    prev->fnFinD                = previousFinish;
    prev->fnEstD                = previousEst;
    prev->fnPayloadD            = previousPayload;
    prev->fnPauseD              = previousPause;
    prev->fnResumeD             = previousResume;
    next->fnInitU               = childInit;
    next->fnPayloadU            = childPayload;
    next->fnFinU                = childFinish;
    next->fnPauseU              = childPause;
    next->fnResumeU             = childResume;
    tunnel_chain_t *chain       = tunnelchainCreate(1);
    chain->masterpool_line_pool = masterpoolCreateWithCapacity(8);
    uint32_t item_size;
    require(tunnelchainTryComputeLineItemSize(proxy->lstate_size, &item_size), "item size");
    chain->line_pools[0] =
        genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(chain->masterpool_line_pool, item_size, 4);
    proxy->chain = chain;
    localAuthentication(chain);

    const char *get      = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: ignored.test\r\n\r\n";
    const char *fix_case = getenv("HPS_FIX_CASE");
    if (! fix_case || ! stringCompare(fix_case, "R1"))
        pipelinePressure(chain, get);
    if (! fix_case || ! stringCompare(fix_case, "R3"))
        responseEof(chain, get);
    for (unsigned event = 1; event <= 5; ++event)
    {
        resetClient(chain);
        close_on = event;
        sendBytes(client, false, get);
        if (event >= 4)
        {
            httpproxyserverTunnelDownStreamPause(proxy, child);
            if (event == 5)
                httpproxyserverTunnelDownStreamResume(proxy, child);
        }
        require(! lineIsAlive(client) && child == NULL, "re-entrant close did not settle both lines");
        require(closes == 1, "child closed more than once");
        lineUnref(client);
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "line reference leak");
    }
    resetClient(chain);
    sendBytes(client, false, get);
    sendBytes(client, false, get);
    require(opens == 1 && establishments == 1, "same authority did not reuse child");
    sendBytes(client, false, "GET http://127.0.0.1:81/b HTTP/1.1\r\nHost: a\r\n\r\n");
    require(opens == 2 && closes == 1 && establishments == 1, "destination replacement or Est count");
    line_t *lost = child;
    lineRef(lost);
    httpproxyserverTunnelDownStreamFinish(proxy, lost);
    require(! lineIsAlive(lost) && lineIsAlive(client), "idle child loss killed client or retained child");
    lineUnref(lost);
    child = NULL;
    sendBytes(client, false, get);
    require(opens == 3 && establishments == 1, "idle child loss prevented a fresh request");
    clientClose();
    lineUnref(client);

    resetClient(chain);
    refuse = true;
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && strstr(received, "502") && ! strstr(received, "200"),
            "CONNECT failure became success");
    lineUnref(client);

    for (size_t split = 1; split < stringLength(get); ++split)
    {
        resetClient(chain);
        char prefix[256];
        memoryCopy(prefix, get, split);
        prefix[split] = 0;
        sendBytes(client, false, prefix);
        require(opens == 0, "partial request header opened destination");
        sendBytes(client, false, get + split);
        require(opens == 1 && strstr(received, "\r\n\r\nok"), "fragmented header lost bytes");
        clientClose();
        lineUnref(client);
    }
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, "POST http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n");
    httpproxyserverTunnelDownStreamPause(proxy, child);
    sendBytes(client, false, "abc");
    require(request_writes == 1, "upload crossed Pause");
    httpproxyserverTunnelDownStreamResume(proxy, child);
    require(request_writes == 2, "upload did not resume");
    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for (size_t i = 0; i < stringLength(response); ++i)
    {
        char byte[] = {response[i], 0};
        sendBytes(child, true, byte);
    }
    require(strstr(received, "\r\n\r\nok") != NULL, "fragmented response lost bytes");
    clientClose();
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokUNSOLICITED");
    require(! lineIsAlive(client) && opens == 1, "unsolicited response bytes advanced exchange");
    lineUnref(client);

    resetClient(chain);
    automatic_response = false;
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\nearly");
    sendBytes(child, true, "banner");
    require(client_writes == 0 && request_writes == 0, "paused CONNECT success or early data escaped");
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(strstr(received, "200 Connection Established\r\n\r\nbanner") != NULL && request_writes == 1,
            "CONNECT success/data ordering");
    clientClose();
    lineUnref(client);
    resetClient(chain);
    refuse   = true;
    close_on = 3;
    sendBytes(client, false, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: a\r\n\r\n");
    require(! lineIsAlive(client) && closes == 0, "error write reflected child Finish");
    lineUnref(client);
    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    char informationals[2048] = {0};
    for (unsigned i = 0; i < 33; ++i)
        strcat(informationals, "HTTP/1.1 103 Early Hints\r\n\r\n");
    sendBytes(child, true, informationals);
    require(! lineIsAlive(client) && strstr(received, "502"), "informational limit");
    lineUnref(client);

    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization");
    tunnel_t                      *auth = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
    authenticationclient_tstate_t *ats  = tunnelGetState(auth);
    require(mutexTryInit(&ats->control_mutex) && rwlockTryInit(&ats->users_lock), "auth locks");
    users_t users;
    require(usersCreate(&users), "users table");
    cJSON *user_json = cJSON_Parse("{\"id\":1001,\"password\":\"user:pass\",\"enabled\":true}");
    require(usersAddUserFromJson(&users, user_json), "test account");
    cJSON_Delete(user_json);
    ats->users        = &users;
    ats->users_loaded = ats->authenticated = true;
    ats->users_generation                  = 7;
    hps_tstate_t *pts                      = tunnelGetState(proxy);
    pts->auth_mode                         = kHpsAuthTracked;
    pts->auth                              = auth;
    const char *authenticated_get          = "GET http://127.0.0.1:80/a HTTP/1.1\r\nHost: a\r\n"
                                             "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
    resetClient(chain);
    user_handle_t inherited = {.generation = 1, .user_id = 42};
    lineAddUser(client, &inherited, "inherited", "value");
    for (unsigned i = 0; i < 8; ++i)
        sendBytes(client, false, authenticated_get);
    require(opens == 1 && lineGetUserAuthCount(client) == 1 && lineGetUserAuthCount(child) == 2,
            "stable auth snapshot failed reuse or grew markers");
    require(lineHasAuthenticatedCredentials(child, "user", "pass"), "child raw credentials missing");
    require(lineHasAuthenticatedCredentials(child, "inherited", "value"), "inherited marker lost");
    ++ats->users_generation;
    sendBytes(client, false, authenticated_get);
    require(opens == 2 && closes == 1, "generation change reused old child");
    userSetEnabled(usersLookupByIdentifier(&users, 1001), false);
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 2 && strstr(received, "407"),
            "disabled account bypassed reauthentication");
    lineUnref(client);
    resetClient(chain);
    ats->authenticated = false;
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "unready auth opened destination");
    lineUnref(client);
    resetClient(chain);
    ats->authenticated = true;
    userSetEnabled(usersLookupByIdentifier(&users, 1001), true);
    for (unsigned i = 0; i < kLineMaxUsers; ++i)
        lineAddUser(client, &inherited, NULL, NULL);
    sendBytes(client, false, authenticated_get);
    require(! lineIsAlive(client) && opens == 0 && strstr(received, "503"), "marker capacity did not refuse locally");
    lineUnref(client);
    pts->auth_mode = kHpsAuthNone;
    pts->auth      = NULL;
    usersDestroy(&users);
    rwlockDestroy(&ats->users_lock);
    mutexDestroy(&ats->control_mutex);
    tunnelDestroy(auth);

    resetClient(chain);
    automatic_response = false;
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    require(client_writes == 0, "payload crossed Pause");
    httpproxyserverTunnelUpStreamResume(proxy, client);
    require(strstr(received, "\r\n\r\nok") != NULL, "Resume lost response order");
    sendBytes(client, false, get);
    httpproxyserverTunnelUpStreamPause(proxy, client);
    sendBytes(child, true, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    httpproxyserverTunnelOnWorkerQuiesce(proxy, 0, NULL);
    httpproxyserverTunnelOnWorkerStop(proxy, 0, NULL);
    require(child == NULL && lineIsAlive(client), "drain borrowed/owned distinction");
    sendBytes(client, false, get);
    require(opens == 1, "late drain payload reopened a child");
    clientClose();
    lineUnref(client);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "final line leak");
    httpproxyserverTunnelDestroy(proxy, NULL);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    wloopDestroy(&loop);
    testWorkerUnbindWID();
    threadsafegenericpoolDestroy(io_pool);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(ios);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(ios);
    puts("http_proxy_server_lifecycle: passed");
    return 0;
}
