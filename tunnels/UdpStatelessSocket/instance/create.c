#include "structure.h"

#include "loggers/network_logger.h"

static tunnel_t *udpstatelesssocketTunnelCreateFail(tunnel_t *t)
{
    udpstatelesssocketTunnelDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}

static void udpstatelesssocketTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tunnelDefaultOnChain(t, chain);
    if (startupFailurePending())
        return;
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    chain                              = tunnelGetChain(t);
    tunnelchainInsert(chain, state->dns_provider);
    if (startupFailurePending())
        return;
    discard domainresolverTunnelAttachEmbedded(state->dns_provider, t, NULL);
}

static bool udpstatelesssocketCreateDnsProvider(tunnel_t *t, node_t *node)
{
    udpstatelesssocket_tstate_t *state    = tunnelGetState(t);
    const dns_policy_defaults_t  defaults = {
         .resolve          = true,
         .strategy         = kDsInvalid,
         .core_strategy    = GSTATE.domain_strategy,
         .require_dns_next = true,
    };
    if (! dnsPolicyParseSettings(
            &state->dns_policy, node->node_settings_json, &defaults, "UdpStatelessSocket->settings"))
        return false;
    const cJSON *policy          = cJSON_GetObjectItemCaseSensitive(node->node_settings_json, "dns-behaviour");
    state->dns_strategy_override = cJSON_GetObjectItemCaseSensitive(policy, "strategy") != NULL;
    state->dns_provider_settings = dnsPolicyCreateResolverSettings(&state->dns_policy);
    if (! nodeConfigureChild(&state->dns_provider_node,
                             nodeDomainResolverGet(),
                             node,
                             ".dns-provider",
                             kNodeChildLinkNone,
                             state->dns_provider_settings))
        return false;
    state->dns_provider_node.flags |= kNodeFlagNoChain;
    state->dns_provider_node.can_have_prev         = false;
    state->dns_provider_node.can_have_next         = false;
    state->dns_provider_node.layer_group           = kNodeLayer4;
    state->dns_provider_node.layer_group_prev_node = kNodeLayerNone;
    state->dns_provider_node.layer_group_next_node = kNodeLayerNone;
    state->dns_provider                            = nodemanagerCreateTunnelInstance(&state->dns_provider_node);
    state->dns_provider_node.instance              = state->dns_provider;
    return state->dns_provider != NULL;
}

tunnel_t *udpstatelesssocketTunnelCreate(node_t *node)
{
    /* Head-only placement is the supported design, not a temporary restriction.
     * New UDP peer lines always enter the chain through upstream Init. */
    if (! nodeHasNext(node))
    {
        LOGF("UdpStatelessSocket: requires a next node; only chain-head placement is supported");
        return NULL;
    }

    tunnel_t *t = adapterCreate(
        node, sizeof(udpstatelesssocket_tstate_t), sizeof(udpstatelesssocket_lstate_t), kAdapterChainHead);
    if (! t)
    {
        return NULL;
    }

    /* Keep adapterCreate's fatal guards on the unsupported upstream side. */

    t->fnInitD    = &udpstatelesssocketTunnelDownStreamInit;
    t->fnEstD     = &udpstatelesssocketTunnelDownStreamEst;
    t->fnFinD     = &udpstatelesssocketTunnelDownStreamFinish;
    t->fnPayloadD = &udpstatelesssocketTunnelDownStreamPayload;
    t->fnPauseD   = &udpstatelesssocketTunnelDownStreamPause;
    t->fnResumeD  = &udpstatelesssocketTunnelDownStreamResume;

    t->onChain          = &udpstatelesssocketTunnelOnChain;
    t->onPrepare        = &udpstatelesssocketTunnelOnPrepair;
    t->onStart          = &udpstatelesssocketTunnelOnStart;
    t->onWorkerQuiesce  = &udpstatelesssocketTunnelOnWorkerQuiesce;
    t->onWorkerStop     = &udpstatelesssocketTunnelOnWorkerStop;
    t->onDestroy        = &udpstatelesssocketTunnelDestroy;

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(! mutexTryInit(&state->dns_cache_mutex)))
    {
        LOGF("UdpStatelessSocket: failed to initialize DNS cache mutex");
        tunnelDestroy(t);
        return NULL;
    }

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings (object field) : The object was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    if (! getStringFromJsonObject(&(state->listen_address), settings, "listen-address"))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-address (string field) : The data was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }
    if (! addressIsIp(state->listen_address))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-address (string field) : The data is not a valid ip "
             "address");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    const char         *source_ip_value  = NULL;
    json_value_status_t source_ip_status = jsonGetObjectNonEmptyString(settings, "source-ip", &source_ip_value);
    if (source_ip_status == kJsonValueInvalid)
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->source-ip (string field) : The value was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }
    if (source_ip_status == kJsonValuePresent)
    {
        if (! addressIsIp(source_ip_value))
        {
            LOGF("JSON Error: UdpStatelessSocket->settings->source-ip (string field) : The value must be a valid IP "
                 "address");
            return udpstatelesssocketTunnelCreateFail(t);
        }
        char *source_ip = stringDuplicate(source_ip_value);
        memoryFree(state->listen_address);
        state->listen_address       = source_ip;
        state->source_ip_configured = true;
    }

    const char *interface_value = NULL;
    switch (jsonGetObjectNonEmptyString(settings, "interface", &interface_value))
    {
    case kJsonValueMissing:
        break;
    case kJsonValuePresent:
        state->interface_name = stringDuplicate(interface_value);
        break;
    case kJsonValueInvalid:
        LOGF("JSON Error: UdpStatelessSocket->settings->interface (string field) : The value was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    state->fwmark        = -1;
    int64_t fwmark_value = -1;
    switch (jsonGetObjectIntegerInRange(settings, "fwmark", INT_MIN, INT_MAX, &fwmark_value))
    {
    case kJsonValueMissing:
        break;
    case kJsonValuePresent:
        state->fwmark = (int) fwmark_value;
        break;
    case kJsonValueInvalid:
        LOGF("JSON Error: UdpStatelessSocket->settings->fwmark (integer field) : The value was invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    switch (jsonGetObjectBoolean(settings, "verbose", &state->verbose))
    {
    case kJsonValueMissing:
    case kJsonValuePresent:
        break;
    case kJsonValueInvalid:
        LOGF("JSON Error: UdpStatelessSocket->settings->verbose (boolean field) : The value was invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->send_buffer_size,
                                                    settings,
                                                    "large-send-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->large-send-buffer (boolean-or-positive-integer field) : The "
             "value was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->recv_buffer_size,
                                                    settings,
                                                    "large-recv-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->large-recv-buffer (boolean-or-positive-integer field) : The "
             "value was empty or invalid");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    int64_t listen_port;
    if (jsonGetObjectIntegerInRange(settings, "listen-port", 0, 65535, &listen_port) != kJsonValuePresent)
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-port (integer field) : The data was missing or not in "
             "the range 0-65535");
        return udpstatelesssocketTunnelCreateFail(t);
    }
    state->listen_port = (uint16_t) listen_port;

    if (! udpstatelesssocketCreateDnsProvider(t, node))
        return udpstatelesssocketTunnelCreateFail(t);

    state->dns_pending = memoryCalloc(getWorkersCount(), sizeof(*state->dns_pending));
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        bufferbudgetInit(
            &state->dns_pending[wid].budget,
            (buffer_budget_cost_t) {kUdpStatelessSocketDnsPendingBytes, kUdpStatelessSocketDnsPendingCharge});

    atomic_init(&state->socket.retired, false);
    state->socket.idle_tables       = memoryAllocateZero(sizeof(*state->socket.idle_tables) * getWorkersCount());
    state->send_request_master_pool = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    if (UNLIKELY(state->send_request_master_pool == NULL))
    {
        LOGF("UdpStatelessSocket: failed to create send-request master pool");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    state->send_request_pools = memoryAllocateZero(sizeof(*state->send_request_pools) * getWorkersCount());
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        state->send_request_pools[wid] = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(
            state->send_request_master_pool, sizeof(udpstatelesssocket_send_request_t), (8) + RAM_PROFILE);
        if (UNLIKELY(state->send_request_pools[wid] == NULL))
        {
            LOGF("UdpStatelessSocket: failed to create send-request pool for worker %d", (int) wid);
            return udpstatelesssocketTunnelCreateFail(t);
        }
    }

    return t;
}
