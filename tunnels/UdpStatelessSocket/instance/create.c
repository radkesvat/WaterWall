#include "structure.h"

#include "loggers/network_logger.h"

static tunnel_t *udpstatelesssocketTunnelCreateFail(tunnel_t *t)
{
    udpstatelesssocketTunnelDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}

tunnel_t *udpstatelesssocketTunnelCreate(node_t *node)
{
    tunnel_t *t =
        adapterCreate(node, sizeof(udpstatelesssocket_tstate_t), sizeof(udpstatelesssocket_lstate_t), kAdapterChainEnd);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &udpstatelesssocketTunnelUpStreamInit;
    t->fnEstU     = &udpstatelesssocketTunnelUpStreamEst;
    t->fnFinU     = &udpstatelesssocketTunnelUpStreamFinish;
    t->fnPayloadU = &udpstatelesssocketTunnelUpStreamPayload;
    t->fnPauseU   = &udpstatelesssocketTunnelUpStreamPause;
    t->fnResumeU  = &udpstatelesssocketTunnelUpStreamResume;

    t->fnInitD    = &udpstatelesssocketTunnelDownStreamInit;
    t->fnEstD     = &udpstatelesssocketTunnelDownStreamEst;
    t->fnFinD     = &udpstatelesssocketTunnelDownStreamFinish;
    t->fnPayloadD = &udpstatelesssocketTunnelDownStreamPayload;
    t->fnPauseD   = &udpstatelesssocketTunnelDownStreamPause;
    t->fnResumeD  = &udpstatelesssocketTunnelDownStreamResume;

    t->onPrepare        = &udpstatelesssocketTunnelOnPrepair;
    t->onStart          = &udpstatelesssocketTunnelOnStart;
    t->onQuiesceRequest = &udpstatelesssocketTunnelOnQuiesceRequest;
    t->onQuiesceWait    = &udpstatelesssocketTunnelOnQuiesceWait;
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
    state->async_session = tunnelasyncsessionCreate(t, "UdpStatelessSocket");
    if (UNLIKELY(state->async_session == NULL))
    {
        LOGF("UdpStatelessSocket: failed to create async callback session");
        return udpstatelesssocketTunnelCreateFail(t);
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
        if (source_ip == NULL)
        {
            LOGF("UdpStatelessSocket: failed to duplicate source-ip");
            return udpstatelesssocketTunnelCreateFail(t);
        }
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
        if (state->interface_name == NULL)
        {
            LOGF("UdpStatelessSocket: failed to duplicate interface");
            return udpstatelesssocketTunnelCreateFail(t);
        }
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

    state->socket.idle_tables = memoryAllocateZero(sizeof(*state->socket.idle_tables) * getWorkersCount());
    if (UNLIKELY(state->socket.idle_tables == NULL))
    {
        LOGF("UdpStatelessSocket: failed to allocate worker idle-table slots");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    state->send_request_master_pool = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    if (UNLIKELY(state->send_request_master_pool == NULL))
    {
        LOGF("UdpStatelessSocket: failed to create send-request master pool");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    state->send_request_pools = memoryAllocateZero(sizeof(*state->send_request_pools) * getTotalWorkersCount());
    if (UNLIKELY(state->send_request_pools == NULL))
    {
        LOGF("UdpStatelessSocket: failed to allocate send-request worker-pool slots");
        return udpstatelesssocketTunnelCreateFail(t);
    }

    for (wid_t wid = 0; wid < getTotalWorkersCount(); ++wid)
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
