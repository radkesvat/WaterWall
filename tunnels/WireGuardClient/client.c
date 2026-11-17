#include "WireGuardClient/interface.h"
#include "WireGuardCommon/dispatch.h"
#include "WireGuardCommon/engine.h"
#include "loggers/network_logger.h"

typedef struct carrier_line_s
{
    bool owned;
} carrier_line_t;

typedef struct client_s
{
    wireguard_device_t   engine;
    wireguard_dispatch_t dispatch;
    tunnel_t            *tunnel;
    line_t              *carrier; /* Owned normal, worker 0. Inner lines are chain packet lines. */
    uint64_t             carrier_id;
    address_context_t    endpoint;
    wtimer_t            *timer;
    uint32_t             last_attempt;
    bool                 attempted;
    bool                 paused;
    bool                 established;
    sbuf_t              *pending[128];
    unsigned             pending_head, pending_count;
    size_t               pending_charge;
} client_t;

static void absorb(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static line_t *ensureCarrier(client_t *state)
{
    assert(currentThreadOwnsWorker(0));
    if (LIKELY(state->carrier != NULL))
        return state->carrier;
    const uint32_t now = getTickMS();
    if (! atomic_load(&state->dispatch.open) || (state->attempted && now - state->last_attempt < 400))
        return NULL;
    state->attempted    = true;
    state->last_attempt = now;
    if (UNLIKELY(state->carrier_id == UINT64_MAX))
    {
        LOGF("WireGuardClient: carrier identity exhausted");
        abortProgramNow(1);
    }
    ++state->carrier_id;
    line_t *line                  = lineCreate(tunnelchainGetLinePools(state->tunnel->chain), 0);
    state->carrier                = line;
    carrier_line_t *carrier_state = lineGetState(line, state->tunnel);
    memoryZeroAligned32(carrier_state, state->tunnel->lstate_size);
    carrier_state->owned = true;
    state->paused        = false;
    state->established   = false;
    addresscontextCopy(lineGetDestinationAddressContext(line), &state->endpoint);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(line), IP_PROTO_UDP);
    if (! lineCallWithRef(line, tunnelNextUpStreamInit, state->tunnel))
        return NULL;
    return state->carrier == line ? line : NULL;
}

static bool output(void *context, sbuf_t *packet, wireguard_peer_t *selected_peer, const ip_addr_t *ip, uint16_t port)
{
    discard   selected_peer;
    discard   ip;
    discard   port;
    client_t *state = context;
    line_t   *line  = ensureCarrier(state);
    if (line == NULL || state->paused || ! state->established)
    {
        reuseBuffer(packet);
        return false;
    }
    discard lineCallWithRefWithBuf(line, tunnelNextUpStreamPayload, state->tunnel, packet);
    return true;
}

static void inner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard   peer;
    client_t *state = context;
    line_t   *line  = tunnelchainGetWorkerPacketLine(state->tunnel->chain, 0);
    tunnelPrevDownStreamPayload(state->tunnel, line, packet);
}

static bool sessionReady(const client_t *state)
{
    const wireguard_keypair_t *key = &state->engine.peers[0].curr_keypair;
    return key->valid && (key->initiator || key->last_rx != 0);
}
static void flushPending(client_t *state)
{
    while (state->pending_count > 0 && sessionReady(state))
    {
        sbuf_t *packet                      = state->pending[state->pending_head];
        state->pending[state->pending_head] = NULL;
        state->pending_head                 = (state->pending_head + 1U) % 128U;
        --state->pending_count;
        state->pending_charge -= sbufGetAllocationCharge(packet);
        wireguardCommonSendInner(&state->engine, packet);
    }
}

static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    discard   argument;
    client_t *state = tunnelGetState(t);
    discard   ensureCarrier(state);
    if (LIKELY(sessionReady(state)))
    {
        flushPending(state);
        wireguardCommonSendInner(&state->engine, packet);
        return;
    }
    const size_t charge = sbufGetAllocationCharge(packet);
    if (state->pending_count == 128 || charge > 1024U * 1024U - state->pending_charge)
    {
        reuseBuffer(packet);
        return;
    }
    state->pending[(state->pending_head + state->pending_count) % 128U] = packet;
    ++state->pending_count;
    state->pending_charge += charge;
}

static void payloadUp(tunnel_t *t, line_t *l, sbuf_t *packet)
{
    assert(tunnelchainIsWorkerPacketLine(t->chain, l));
    discard   l;
    client_t *state = tunnelGetState(t);
    wireguardDispatch(&state->dispatch, 0, t, packet, NULL, sendInner, NULL);
}

static void payloadDown(tunnel_t *t, line_t *l, sbuf_t *packet)
{
    client_t *state = tunnelGetState(t);
    assert(currentThreadOwnsWorker(0));
    if (UNLIKELY(state->carrier != l || ! state->established || ! atomic_load(&state->dispatch.open)))
    {
        lineReuseBuffer(l, packet);
        return;
    }
    wireguardCommonReceiveOnCarrier(&state->engine, packet, state->carrier_id);
    flushPending(state);
}

static void finishDown(tunnel_t *t, line_t *l)
{
    client_t *state = tunnelGetState(t);
    assert(currentThreadOwnsWorker(0) && ! tunnelchainIsWorkerPacketLine(t->chain, l));
    carrier_line_t *carrier_state = lineGetState(l, t);
    if (UNLIKELY(! carrier_state->owned))
    {
        LOGF("WireGuardClient: Finish reached a normal line outside its carrier inventory");
        abortProgramNow(1);
    }
    memoryZeroAligned32(carrier_state, t->lstate_size);
    if (state->carrier == l)
    {
        state->carrier     = NULL;
        state->established = false;
        state->paused      = false;
    }
    lineDestroy(l);
}

static void finishUp(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("WireGuardClient: unexpected Finish on packet input");
    abortProgramNow(1);
}

static void estDown(tunnel_t *t, line_t *l)
{
    client_t *state = tunnelGetState(t);
    if (state->carrier == l)
        state->established = true;
}
static void pauseDown(tunnel_t *t, line_t *l)
{
    client_t *state = tunnelGetState(t);
    if (state->carrier == l)
        state->paused = true;
}
static void resumeDown(tunnel_t *t, line_t *l)
{
    client_t *state = tunnelGetState(t);
    if (state->carrier == l)
        state->paused = false;
}

static void tick(wtimer_t *timer)
{
    client_t *state = weventGetUserdata(timer);
    if (atomic_load(&state->dispatch.open))
    {
        discard ensureCarrier(state);
        wireguardCommonLoop(&state->engine);
        flushPending(state);
    }
}
static void start(tunnel_t *t)
{
    client_t *state               = tunnelGetState(t);
    state->engine.peers[0].active = true;
    state->timer                  = wtimerAdd(getWorkerLoop(0), tick, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->timer == NULL)
    {
        startupFailureRecord(1);
        return;
    }
    weventSetUserData(state->timer, state);
}
static void quiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    client_t *state = tunnelGetState(t);
    atomic_store(&state->dispatch.open, false);
}
static void quiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    client_t *state = tunnelGetState(t);
    if (wid == 0 && state->timer != NULL)
    {
        wtimerDelete(state->timer);
        state->timer = NULL;
    }
}
static void stopWorker(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    client_t *state = tunnelGetState(t);
    if (wid != 0)
        return;
    while (state->pending_count > 0)
    {
        sbuf_t *packet                      = state->pending[state->pending_head];
        state->pending[state->pending_head] = NULL;
        state->pending_head                 = (state->pending_head + 1U) % 128U;
        --state->pending_count;
        state->pending_charge -= sbufGetAllocationCharge(packet);
        reuseBuffer(packet);
    }
    if (state->carrier == NULL)
        return;
    line_t *line   = state->carrier;
    state->carrier = NULL;
    memoryZeroAligned32(lineGetState(line, t), t->lstate_size);
    lineRef(line);
    tunnelNextUpStreamFinish(t, line);
    if (lineIsAlive(line))
        lineDestroy(line);
    lineUnref(line);
}
static void destroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    client_t *state = tunnelGetState(t);
    assert(state->pending_count == 0 && state->carrier == NULL && atomic_load(&state->dispatch.count) == 0);
    addresscontextReset(&state->endpoint);
    wireguardDeviceDestroy(&state->engine);
    tunnelDestroy(t);
}

static bool endpointParse(address_context_t *endpoint, const cJSON *value)
{
    if (! cJSON_IsString(value) || value->valuestring == NULL)
        return false;
    char *text = stringDuplicate(value->valuestring), *host = text, *colon = strrchr(text, ':');
    bool  result = false;
    if (colon == NULL)
        goto finish;
    *colon++ = '\0';
    char         *end;
    unsigned long port = strtoul(colon, &end, 10);
    if (*colon == '\0' || *end != '\0' || port == 0 || port > UINT16_MAX)
        goto finish;
    size_t length = strlen(host);
    if (length >= 2 && host[0] == '[' && host[length - 1] == ']')
    {
        host[length - 1] = '\0';
        ++host;
        length -= 2;
    }
    if (length == 0 || length > UINT8_MAX)
        goto finish;
    if (! addresscontextSetIpAddress(endpoint, host))
        addresscontextDomainSet(endpoint, host, (uint8_t) length);
    addresscontextSetPort(endpoint, (uint16_t) port);
    addresscontextSetOnlyProtocol(endpoint, IP_PROTO_UDP);
    result = true;
finish:
    memoryFree(text);
    return result;
}

static tunnel_t *create(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(client_t), sizeof(carrier_line_t));
    if (t == NULL)
        return NULL;
    client_t *state = tunnelGetState(t);
    state->tunnel   = t;
    wireguardDispatchInit(&state->dispatch);
    const cJSON *settings = node->node_settings_json;
    const cJSON *key      = cJSON_GetObjectItemCaseSensitive(settings, "privatekey");
    const cJSON *peers    = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    uint8_t      index    = 0;
    if (! jsonObjectFieldStringsAreExact(settings, "privatekey") || ! cJSON_IsString(key) || ! cJSON_IsArray(peers) ||
        cJSON_GetArraySize(peers) != 1 ||
        ! wireguardCommonInit(
            &state->engine, key->valuestring, state, (wireguard_callbacks_t) {.output = output, .inner = inner}) ||
        ! wireguardCommonAddConfiguredPeer(&state->engine, cJSON_GetArrayItem(peers, 0), &index) ||
        ! jsonObjectFieldStringsAreExact(cJSON_GetArrayItem(peers, 0), "endpoint") ||
        ! endpointParse(&state->endpoint, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(peers, 0), "endpoint")))
    {
        LOGF("WireGuardClient: requires privatekey and exactly one peer with publickey, allowedips and endpoint "
             "host:port");
        destroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    t->fnInitU          = absorb;
    t->fnEstU           = absorb;
    t->fnEstD           = estDown;
    t->fnPauseU         = absorb;
    t->fnPauseD         = pauseDown;
    t->fnResumeU        = absorb;
    t->fnResumeD        = resumeDown;
    t->fnFinU           = finishUp;
    t->fnFinD           = finishDown;
    t->fnPayloadU       = payloadUp;
    t->fnPayloadD       = payloadDown;
    t->onStart          = start;
    t->onQuiesceRequest = quiesceRequest;
    t->onWorkerQuiesce  = quiesce;
    t->onWorkerStop     = stopWorker;
    t->onDestroy        = destroy;
    return t;
}

node_t nodeWireGuardClientGet(void)
{
    const char *type = "WireGuardClient";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, strlen(type)),
                     .version               = 1,
                     .createHandle          = create,
                     .required_padding_left = 16,
                     .layer_group           = kNodeLayer3 | kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer3,
                     .layer_group_next_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
