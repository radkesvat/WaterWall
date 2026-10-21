/* CTest: waterwall.authentication_ingress_unit
 * Real paired authentication handlers: maximum frames, fragmentation, coalescing,
 * callback reentry and terminal cleanup, with both supported medium pool tiers. */
#include "AuthenticationClient/structure.h"
#include "authentication_sync_peer.h"
#include "loggers/network_logger.h"
#include "test_assert.h"
#include "wevent.h"
#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return 100000000;
}

uint32_t __wrap_fastRand32(void);
uint32_t __wrap_fastRand32(void)
{
    return 0; /* Deterministic lower jitter bound in fake-clock fixtures. */
}

static worker_t                   worker;
static buffer_pool_t             *pools[1];
static wloop_t                   *loops[1];
static threadsafe_generic_pool_t *wios[1];
static master_pool_t             *ordinary[3], *line_master, *message_master, *wio_master;
static tunnel_chain_t            *chain;
static tunnel_t                  *client, *server, *transport;
static line_t                    *observed_line;
static bool                       capture, fragment, raw, inject, finish_output, finish_input, flood;
static bool                       client_nested, client_flood;
static uint8_t                   *captured;
static size_t                     captured_length;
static uint32_t                   response_ids[8];
static unsigned                   response_count, nested_count;
static uint64_t                   delivered;
static uint32_t                   response_remaining, largest_response;
static unsigned                   nested_suffix_mode;

static authenticationclient_tstate_t *state(void)
{
    return tunnelGetState(client);
}

static sbuf_t *bytesBuffer(const void *data, uint32_t length)
{
    sbuf_t *b = bufferpoolGetBestFit(pools[0], length, 64);
    sbufSetLength(b, length);
    if (data != NULL)
        memoryCopy(sbufGetMutablePtr(b), data, length);
    else
        memoryZero(sbufGetMutablePtr(b), length);
    return b;
}

static void put32(uint8_t *p, uint32_t value)
{
    value = htonl(value);
    memoryCopy(p, &value, sizeof(value));
}

/* Ordinary maximum-size envelopes require an authenticated token. */
static sbuf_t *request(uint32_t correlation, uint32_t frame_length)
{
    require(frame_length >= 9, "request frame too short");
    sbuf_t  *b = bytesBuffer(NULL, frame_length + 68);
    uint8_t *p = sbufGetMutablePtr(b);
    put32(p, frame_length + 64);
    memoryCopy(p + 4, state()->token, 64);
    p[68] = kAuthenticationClientRequestTypePing;
    put32(p + 69, correlation);
    put32(p + 73, frame_length - 9);
    return b;
}

static sbuf_t *join(sbuf_t *first, sbuf_t *second)
{
    const uint32_t a = sbufGetLength(first), b = sbufGetLength(second);
    sbuf_t        *combined = bytesBuffer(NULL, a + b);
    memoryCopy(sbufGetMutablePtr(combined), sbufGetRawPtr(first), a);
    memoryCopy(sbufGetMutablePtr(combined) + a, sbufGetRawPtr(second), b);
    lineReuseBuffer(observed_line, first);
    lineReuseBuffer(observed_line, second);
    return combined;
}

static void finish(tunnel_t *t, line_t *l)
{
    discard t;
    tunnelDownStreamFin(client, l);
}

static void established(tunnel_t *t, line_t *l)
{
    discard t;
    require(observed_line == NULL, "unexpected extra control line");
    observed_line = l;
    lineRef(l); /* Retain allocation for terminal state/ownership checks. */
    tunnelDownStreamEst(client, l);
}

static void output(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    if (response_remaining == 0)
    {
        uint32_t size;
        require(sbufGetLength(b) >= 4, "short response prefix");
        memoryCopy(&size, sbufGetRawPtr(b), 4);
        response_remaining = ntohl(size) + 4;
        largest_response   = max(largest_response, response_remaining);
    }
    require(sbufGetLength(b) <= response_remaining, "response chunks crossed envelope boundary");
    response_remaining -= sbufGetLength(b);
    if (capture)
    {
        captured = memoryReAllocate(captured, captured_length + sbufGetLength(b));
        memoryCopy(captured + captured_length, sbufGetRawPtr(b), sbufGetLength(b));
        captured_length += sbufGetLength(b);
        lineReuseBuffer(l, b);
        return;
    }
    if (raw)
    {
        require(sbufGetLength(b) >= 29 && response_count < 8, "unexpected raw response");
        uint32_t id;
        memoryCopy(&id, (const uint8_t *) sbufGetRawPtr(b) + 21, 4);
        response_ids[response_count++] = ntohl(id);
        lineReuseBuffer(l, b);
        if (inject)
        {
            inject = false;
            tunnelUpStreamPayload(server, l, request(3, 9));
        }
        if (nested_suffix_mode != 0)
        {
            const unsigned mode = nested_suffix_mode;
            nested_suffix_mode  = 0;
            sbuf_t *successor   = request(3, mode == 1 ? 9 : 64 * 1024);
            memoryZero(sbufGetMutablePtr(successor) + 4, 64);
            if (mode == 1)
            {
                sbuf_t *prefix = bytesBuffer(sbufGetRawPtr(successor), 2);
                tunnelUpStreamPayload(server, l, join(request(2, 64 * 1024), prefix));
                require(lineIsAlive(l), "large valid envelope plus tiny incomplete successor was rejected");
            }
            else if (mode == 2)
            {
                sbuf_t *header = bytesBuffer(sbufGetRawPtr(successor), 68);
                tunnelUpStreamPayload(server, l, join(request(2, 64 * 1024), header));
                require(! lineIsAlive(l), "valid first token elevated an oversized unknown-token successor");
            }
            else
            {
                tunnelUpStreamPayload(server, l, bytesBuffer((const uint8_t *) sbufGetRawPtr(successor) + 2, 66));
                require(! lineIsAlive(l), "older unread suffix lent its allowance to a split unknown-token header");
            }
            lineReuseBuffer(l, successor);
        }
        if (flood)
        {
            flood = false;
            for (unsigned i = 0; i < 2048 && lineIsAlive(l); ++i)
            {
                ++nested_count;
                tunnelUpStreamPayload(server, l, request(100 + i, 64 * 1024));
            }
        }
        if (finish_output)
        {
            finish_output = false;
            authenticationclientCloseControlLine(client, l, true);
        }
        return;
    }
    if (client_nested)
    {
        client_nested = false;
        require(sbufGetLength(b) >= 29, "nested response missing envelope");
        /* Its real revision matches its page metadata. The older queued Pong
         * below carries revision 2, so the final revision 1 proves FIFO. */
    }
    if (client_flood)
    {
        client_flood = false;
        for (unsigned i = 0; i < 2048 && lineIsAlive(l); ++i)
        {
            ++nested_count;
            sbuf_t  *extra = bytesBuffer(NULL, 64 * 1024);
            uint8_t *p     = sbufGetMutablePtr(extra);
            put32(p, 64 * 1024 - 4);
            p[20] = kAuthenticationClientResponseTypePong;
            put32(p + 21, UINT32_MAX);
            put32(p + 25, 64 * 1024 - 29);
            tunnelDownStreamPayload(client, l, extra);
        }
        lineReuseBuffer(l, b);
        return;
    }
    delivered += sbufGetLength(b);
    if (! fragment)
    {
        tunnelDownStreamPayload(client, l, b);
        return;
    }
    /* Split the first header bytes and each normal output chunk. The copies
     * still use real pool tiers, so tiny payloads do not imply tiny capacity. */
    uint32_t       offset = 0;
    const uint32_t length = sbufGetLength(b);
    while (offset < length && lineIsAlive(l))
    {
        const uint32_t n    = min(length - offset, offset < 5 ? 1U : 8191U);
        sbuf_t        *part = bytesBuffer((const uint8_t *) sbufGetRawPtr(b) + offset, n);
        offset += n;
        tunnelDownStreamPayload(client, l, part);
    }
    lineReuseBuffer(l, b);
}

static void input(tunnel_t *t, line_t *l, sbuf_t *b)
{
    if (finish_input && sbufGetLength(b) >= 77 &&
        ((const uint8_t *) sbufGetRawPtr(b))[68] == kAuthenticationClientRequestTypeGetAllUsers)
    {
        finish_input = false;
        lineReuseBuffer(l, b);
        authenticationclientCloseControlLine(client, l, true);
        return;
    }
    if (! fragment)
    {
        tunnelNextUpStreamPayload(t, l, b);
        return;
    }
    const uint32_t length = sbufGetLength(b);
    uint32_t       offset = 0;
    while (offset < length && lineIsAlive(l))
    {
        const uint32_t n    = min(length - offset, offset < 5 ? 1U : 8191U);
        sbuf_t        *part = bytesBuffer((const uint8_t *) sbufGetRawPtr(b) + offset, n);
        offset += n;
        tunnelNextUpStreamPayload(t, l, part);
    }
    lineReuseBuffer(l, b);
}

static void setup(uint32_t medium)
{
    capture = fragment = raw = inject = finish_output = finish_input = flood = false;
    client_nested = client_flood = false;
    captured                     = NULL;
    captured_length = delivered = 0;
    response_count = nested_count = 0;
    observed_line                 = NULL;
    response_remaining = largest_response = 0;
    nested_suffix_mode                    = 0;
    memoryZero(&worker, sizeof(worker));
    GSTATE.flag_initialized      = true;
    GSTATE.workers_count         = 1;
    GSTATE.workers               = &worker;
    GSTATE.shortcut_buffer_pools = pools;
    GSTATE.shortcut_loops        = loops;
    GSTATE.shortcut_wios_pools   = wios;
    for (unsigned j = 0; j < 3; ++j)
        ordinary[j] = masterpoolCreateWithCapacity(8);
    pools[0] = bufferpoolCreate(ordinary[0], ordinary[1], ordinary[2], 4, 128 * 1024, medium, 4096, 1048576, 1048576);
    require(pools[0] != NULL, "pool creation failed");
    bufferpoolUpdateAllocationPaddings(pools[0], 64, 64, 64, 64);
    wio_master            = masterpoolCreateWithCapacity(16);
    wios[0]               = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 8);
    worker.wid            = 0;
    worker.buffer_pool    = pools[0];
    worker.wios_pool      = wios[0];
    loops[0]              = wloopCreate(WLOOP_FLAG_AUTO_FREE, pools[0], 0);
    worker.loop           = loops[0];
    loops[0]->status      = WLOOP_STATUS_RUNNING;
    mutexInit(&worker.control_mutex);
    testWorkerBindWID(0);
    message_master = masterpoolCreateWithCapacity(16);
    workerMessagesInstallMasterPoolCallbacks(message_master);
    GSTATE.masterpool_messages = message_master;
    workerMessagesInit(&worker);
    require(workerMessagesOpenAdmission(&worker), "worker admission failed");

    client    = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    transport = tunnelCreate(NULL, 0, 0);
    require(client != NULL && transport != NULL, "tunnel creation failed");
    server                = authTestPeerCreate(client->lstate_size);
    transport->fnPayloadU = input;
    transport->fnPayloadD = output;
    transport->fnEstD     = established;
    transport->fnFinD     = finish;
    client->fnFinD        = authenticationclientTunnelDownStreamFinish;
    client->fnEstD        = authenticationclientTunnelDownStreamEst;
    client->fnPayloadD    = authenticationclientTunnelDownStreamPayload;
    tunnelBind(client, transport);
    tunnelBind(transport, server);
    chain                = memoryCalloc(1, sizeof(*chain) + sizeof(generic_pool_t *));
    line_master          = masterpoolCreateWithCapacity(16);
    chain->line_pools[0] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        line_master, sizeof(line_t) + client->lstate_size + authTestPeerLineSize(), 8);
    client->chain                     = chain;
    authenticationclient_tstate_t *ts = state();
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->users = memoryAllocateAligned(sizeof(users_t), 32);
    require(usersCreate(ts->users), "client users failed");
    ts->name                  = stringDuplicate("edge-a");
    ts->secret                = stringDuplicate("secret");
    ts->started               = true;
    ts->users_generation      = 1;
    ts->next_correlation_id   = 1;
    ts->reconnect_interval_ms = 10;
    ts->request_timeout_ms    = 1000;
    ts->max_pending_requests  = 64;
    ts->sync_max_users        = kAuthenticationDefaultSyncMaxUsers;
    ts->sync_max_bytes        = kAuthenticationDefaultSyncMaxBytes;
}

static void start(void)
{
    authenticationclientOpenControlLine(client);
    require(observed_line != NULL, "control line was not established");
}

static void teardown(void)
{
    authenticationclientTunnelOnQuiesceRequest(client, wwLifecycleProcessShutdown());
    authenticationclientTunnelOnWorkerQuiesce(client, 0, wwLifecycleProcessShutdown());
    authenticationclientTunnelOnWorkerStop(client, 0, wwLifecycleProcessShutdown());
    workerMessagesCloseAdmission(&worker);
    workerMessagesCleanupPending(&worker);
    require(! lineIsAlive(observed_line), "stop left the owned line alive");
    require(atomicLoadU32Relaxed(&observed_line->refc) == 1, "line reference leak or duplicate destroy");
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnel_t      *t     = i == 0 ? client : server;
        const uint8_t *bytes = lineGetState(observed_line, t);
        for (uint32_t j = 0; j < t->lstate_size; ++j)
            require(bytes[j] == 0, "ingress state survived Finish");
    }
    lineUnref(observed_line);
    authenticationclientTunnelDestroy(client, wwLifecycleProcessShutdown());
    authTestPeerDestroy(server);
    tunnelDestroy(transport);
    workerMessagesDestroy(&worker);
    wloopDestroy(&loops[0]);
    mutexDestroy(&worker.control_mutex);
    require(masterpoolGetCheckedOut(line_master) == 0, "line pool retained a physical reference");
    genericpoolDestroy(chain->line_pools[0]);
    threadsafegenericpoolDestroy(wios[0]);
    bufferpoolDestroy(pools[0]);
    for (unsigned j = 0; j < 3; ++j)
    {
        masterpoolMakeEmpty(ordinary[j]);
        masterpoolDestroy(ordinary[j]);
    }
    masterpoolMakeEmpty(line_master);
    masterpoolMakeEmpty(message_master);
    masterpoolMakeEmpty(wio_master);
    masterpoolDestroy(line_master);
    masterpoolDestroy(message_master);
    masterpoolDestroy(wio_master);
    memoryFree(chain);
    memoryFree(captured);
    testWorkerUnbindWID();
    GSTATE.flag_initialized    = false;
    GSTATE.workers             = NULL;
    GSTATE.masterpool_messages = NULL;
}

static void testMaximumResponse(uint32_t medium, bool fragmented)
{
    setup(medium);
    fragment = fragmented;
    start();
    require(authenticationclientIsReady(client), "initial fragmented exchange failed");
    const size_t notes = authTestPeerPadUsersResponse(
        server, observed_line, kAuthenticationClientMaxResponsePayload - kAuthenticationClientResponseHeaderSize);
    delivered = 0;
    authenticationclientRequestPull(client);
    require(state()->control_line == observed_line && authenticationclientIsReady(client),
            "maximum legal Users response disconnected the client");
    require(largest_response ==
                    kAuthenticationClientMaxResponsePayload + kAuthenticationClientResponseEnvelopeHeaderSize &&
                delivered > largest_response,
            "fixture did not send the exact maximum response");
    require(! state()->pull_in_flight, "maximum response did not complete the pull");
    user_t *user = usersLookupByIdentifier(state()->users, 42);
    require(user != NULL && stringLength(user->notes) == notes && user->notes[notes - 1] == 'a',
            "maximum Users response was truncated or not applied");
    teardown();
}

static void testCombinedResponses(void)
{
    setup(64 * 1024);
    start();
    const size_t notes = authTestPeerPadUsersResponse(
        server, observed_line, kAuthenticationClientMaxResponsePayload - kAuthenticationClientResponseHeaderSize);
    capture = true;
    authenticationclientRequestPull(client);
    require(captured_length ==
                kAuthenticationClientMaxResponsePayload + kAuthenticationClientResponseEnvelopeHeaderSize,
            "captured response was not maximum size");
    /* Append a complete stale response. It must be ignored only after the
     * preceding maximum Users envelope is consumed successfully. */
    sbuf_t *tail = bytesBuffer(NULL, 29);
    put32(sbufGetMutablePtr(tail), 25);
    sbufGetMutablePtr(tail)[20] = kAuthenticationClientResponseTypePong;
    put32(sbufGetMutablePtr(tail) + 21, UINT32_MAX);
    sbuf_t *combined = join(bytesBuffer(captured, (uint32_t) captured_length), tail);
    capture          = false;
    tunnelDownStreamPayload(client, observed_line, combined);
    require(state()->control_line == observed_line && ! state()->pull_in_flight,
            "combined complete response envelopes were rejected");
    user_t *user = usersLookupByIdentifier(state()->users, 42);
    require(user != NULL && stringLength(user->notes) == notes, "combined Users response was not applied");
    teardown();
}

static void testRequestsAndReentry(bool fragmented, bool nested)
{
    setup(64 * 1024);
    start();
    raw              = true;
    inject           = nested;
    sbuf_t *combined = join(request(1, kAuthenticationClientMaxMessagePayload), request(2, 9));
    if (fragmented)
    {
        fragment = true;
        input(transport, observed_line, combined);
    }
    else
        tunnelUpStreamPayload(server, observed_line, combined);
    require(lineIsAlive(observed_line), "legal request envelopes disconnected the line");
    require(response_count == (nested ? 3U : 2U), "legal request envelope was not processed");
    for (unsigned i = 0; i < response_count; ++i)
        require(response_ids[i] == i + 1, "nested request overtook older input");
    teardown();
}

static void testClientReentry(bool exhaust)
{
    setup(64 * 1024);
    start();
    capture = true;
    authenticationclientRequestPull(client);
    const size_t second = captured_length;
    require(second > 29 && state()->pull_in_flight, "first response was not held");
    require(authenticationclientSendPing(client), "second request failed");
    require(captured_length > second + 29, "second response was not held");
    authenticationclientRequestPull(client); /* Runs after the held first pull. */
    memoryZero(captured + 4, 8);
    put32(captured + 8, 1);
    memoryZero(captured + second + 4, 8);
    put32(captured + second + 8, 2);
    capture       = false;
    client_nested = ! exhaust;
    client_flood  = exhaust;
    tunnelDownStreamPayload(client, observed_line, bytesBuffer(captured, (uint32_t) captured_length));
    if (exhaust)
        require(! lineIsAlive(observed_line) && nested_count < 2048, "client nested ingress storage was unbounded");
    else
        require(lineIsAlive(observed_line) && state()->pending_count == 0 && state()->remote_config_revision == 1,
                "client nested response overtook older input");
    teardown();
}

static void deliverIngress(bool to_client, sbuf_t *buffer)
{
    if (to_client)
        tunnelDownStreamPayload(client, observed_line, buffer);
    else
        tunnelUpStreamPayload(server, observed_line, buffer);
}

static void testEmptyDeliveries(void)
{
    for (unsigned side = 0; side < 2; ++side)
    {
        setup(64 * 1024);
        start();
        const bool to_client = side == 0;
        sbuf_t    *message;
        if (to_client)
        {
            capture = true;
            authenticationclientRequestPull(client);
            capture = false;
            require(captured_length > 29 && state()->pull_in_flight, "Users response was not held");
            message = bytesBuffer(captured, (uint32_t) captured_length);
        }
        else
        {
            raw     = true;
            message = request(73, 9);
        }
        const uint8_t *bytes  = sbufGetRawPtr(message);
        const uint32_t length = sbufGetLength(message);
        deliverIngress(to_client, bytesBuffer(bytes, 2));
        for (unsigned i = 0; i < 1030 && lineIsAlive(observed_line); ++i)
            deliverIngress(to_client, bytesBuffer(NULL, 0));
        require(lineIsAlive(observed_line) && response_count == 0,
                "empty deliveries closed the line or completed a partial header");
        if (to_client)
            require(state()->pull_in_flight, "empty responses completed the pending pull");
        deliverIngress(to_client, bytesBuffer(bytes + 2, length - 2));
        lineReuseBuffer(observed_line, message);
        require(lineIsAlive(observed_line), "partial message was corrupted by empty deliveries");
        if (to_client)
            require(! state()->pull_in_flight && state()->pending_count == 0 && authenticationclientIsReady(client),
                    "Users response did not complete after empty deliveries");
        else
            require(response_count == 1 && response_ids[0] == 73,
                    "request did not complete correctly after empty deliveries");
        teardown();
    }
}

static void testTerminalPaths(void)
{
    /* Finish while the client is parsing Session and sending its initial pull. */
    setup(64 * 1024);
    finish_input = true;
    start();
    require(! lineIsAlive(observed_line), "Finish in client response callback did not close the line");
    teardown();

    /* Finish while the server is parsing the first of two coalesced requests. */
    setup(64 * 1024);
    start();
    raw = finish_output = true;
    tunnelUpStreamPayload(server, observed_line, join(request(1, 9), request(2, 9)));
    require(! lineIsAlive(observed_line) && response_count == 1, "server processed input after Finish");
    teardown();

    /* Nested input cannot evade a finite retained-input limit. */
    setup(64 * 1024);
    start();
    raw = flood = true;
    tunnelUpStreamPayload(server, observed_line, request(1, 9));
    require(! lineIsAlive(observed_line) && nested_count < 2048, "nested ingress storage was unbounded");
    teardown();

    for (unsigned side = 0; side < 2; ++side)
    {
        setup(64 * 1024);
        start();
        sbuf_t *bad = bytesBuffer(NULL, 4);
        put32(sbufGetMutablePtr(bad), UINT32_MAX);
        if (side == 0)
            tunnelDownStreamPayload(client, observed_line, bad);
        else
            tunnelUpStreamPayload(server, observed_line, bad);
        require(! lineIsAlive(observed_line), "oversized declared message was not refused");
        teardown();
    }
}

static void testPreauthRetention(void)
{
    setup(64 * 1024);
    start();
    raw               = true;
    sbuf_t *oversized = request(1, 16385);
    memoryZero(sbufGetMutablePtr(oversized) + 4, 64);
    const uint8_t *header = sbufGetRawPtr(oversized);
    tunnelUpStreamPayload(server, observed_line, bytesBuffer(header, 4));
    tunnelUpStreamPayload(server, observed_line, bytesBuffer(header + 4, 63));
    require(lineIsAlive(observed_line), "incomplete token header was prematurely rejected");
    tunnelUpStreamPayload(server, observed_line, bytesBuffer(header + 67, 1));
    require(! lineIsAlive(observed_line) && response_count == 0,
            "oversized pre-auth declaration needed body bytes before refusal");
    lineReuseBuffer(observed_line, oversized);
    teardown();

    setup(64 * 1024);
    start();
    raw             = true;
    sbuf_t *message = request(1, 16384);
    memoryZero(sbufGetMutablePtr(message) + 4, 64);
    sbuf_t *carrier = bytesBuffer(NULL, 2 * 1024 * 1024);
    memoryCopy(sbufGetMutablePtr(carrier), sbufGetRawPtr(message), 68);
    sbufSetLength(carrier, 68);
    tunnelUpStreamPayload(server, observed_line, carrier);
    for (unsigned i = 0; i < 100; ++i)
    {
        size_t bytes, charge, entries;
        authTestPeerInputRetention(server, observed_line, &bytes, &charge, &entries);
        require(bytes == 68 + i && charge <= 128 * 1024 && entries <= 64,
                "pre-auth incomplete input retained oversized backing charge or tiny-fragment runs");
        tunnelUpStreamPayload(server, observed_line, bytesBuffer((const uint8_t *) sbufGetRawPtr(message) + 68 + i, 1));
    }
    tunnelUpStreamPayload(server,
                          observed_line,
                          bytesBuffer((const uint8_t *) sbufGetRawPtr(message) + 168, sbufGetLength(message) - 168));
    require(lineIsAlive(observed_line) && response_count == 1, "maximum bounded pre-auth request did not complete");
    lineReuseBuffer(observed_line, message);
    teardown();
}

static void testNestedSuccessorAllowance(void)
{
    for (unsigned mode = 1; mode <= 3; ++mode)
    {
        setup(64 * 1024);
        start();
        raw                = true;
        nested_suffix_mode = mode;
        if (mode == 3)
        {
            sbuf_t *successor = request(3, 64 * 1024);
            memoryZero(sbufGetMutablePtr(successor) + 4, 64);
            sbuf_t *older = join(request(2, 64 * 1024), bytesBuffer(sbufGetRawPtr(successor), 2));
            tunnelUpStreamPayload(server, observed_line, join(request(1, 9), older));
            lineReuseBuffer(observed_line, successor);
        }
        else
            tunnelUpStreamPayload(server, observed_line, request(1, 9));
        if (mode == 1)
        {
            require(lineIsAlive(observed_line) && response_count == 2 && response_ids[0] == 1 && response_ids[1] == 2,
                    "nested large valid request did not drain before incomplete successor");
            sbuf_t *last = request(3, 9);
            memoryZero(sbufGetMutablePtr(last) + 4, 64);
            tunnelUpStreamPayload(
                server, observed_line, bytesBuffer((const uint8_t *) sbufGetRawPtr(last) + 2, sbufGetLength(last) - 2));
            lineReuseBuffer(observed_line, last);
            require(lineIsAlive(observed_line) && response_count == 3 && response_ids[2] == 3,
                    "small unknown-token successor did not complete after valid envelope");
        }
        teardown();
    }
}

int main(void)
{
    testCaseSet("authentication ingress framing and retention");
    require(createNetworkLogger(NULL, false) != NULL, "logger initialization failed");
    require(globalstateInitializeSecureRandom() && wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    testMaximumResponse(32 * 1024, false);
    testMaximumResponse(64 * 1024, false);
    testMaximumResponse(32 * 1024, true);
    testMaximumResponse(64 * 1024, true);
    testCombinedResponses();
    testRequestsAndReentry(false, false);
    testRequestsAndReentry(true, false);
    testRequestsAndReentry(false, true);
    testClientReentry(false);
    testClientReentry(true);
    testEmptyDeliveries();
    testTerminalPaths();
    testPreauthRetention();
    testNestedSuccessorAllowance();
    wCryptoGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
