#include "structure.h"

#include "loggers/network_logger.h"

static void initializeTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &tcpconnectorTunnelUpStreamInit;
    t->fnEstU     = &tcpconnectorTunnelUpStreamEst;
    t->fnFinU     = &tcpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &tcpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &tcpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &tcpconnectorTunnelUpStreamResume;

    t->onPrepare = &tcpconnectorTunnelOnPrepair;
    t->onStart   = &tcpconnectorTunnelOnStart;
    t->onDestroy = &tcpconnectorTunnelDestroy;
}

static bool parseBasicSettings(tcpconnector_tstate_t *state, const cJSON *settings)
{
    if (!checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpConnector->settings (object field) : The object was empty or invalid");
        return false;
    }

    getBoolFromJsonObjectOrDefault(&(state->option_tcp_no_delay), settings, "nodelay", true);
    getBoolFromJsonObjectOrDefault(&(state->option_tcp_fast_open), settings, "fastopen", false);
    getBoolFromJsonObjectOrDefault(&(state->option_reuse_addr), settings, "reuseaddr", false);
    getIntFromJsonObjectOrDefault(&(state->domain_strategy), settings, "domain-strategy", 0);

    return true;
}

static bool parseDestinationAddress(tcpconnector_tstate_t *state, const cJSON *settings)
{
    state->dest_addr_selected = parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (state->dest_addr_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: TcpConnector->settings->address (string field) : The vaule was empty or invalid");
        return false;
    }

    state->constant_dest_addr.ip_address.type = getIpVersion(state->dest_addr_selected.string);

    if (state->constant_dest_addr.ip_address.type == IPADDR_TYPE_ANY)
    {
        state->constant_dest_addr.type_ip = false;
    }
    else
    {
        state->constant_dest_addr.type_ip = true;
    }

    return true;
}

static void configureIpv4Range(tcpconnector_tstate_t *state, int prefix_length)
{
    if (prefix_length > 32)
    {
        LOGF("TcpConnector: outbound ip/subnet range is invalid");
        terminateProgram(1);
    }
    else if (prefix_length == 32)
    {
        state->outbound_ip_range = 0;
    }
    else
    {
        state->outbound_ip_range = (0xFFFFFFFF & (0x1 << (32 - prefix_length)));
    }
}

static void configureIpv6Range(tcpconnector_tstate_t *state, int prefix_length)
{
    if (64 > prefix_length)
    {
        LOGF("TcpConnector: outbound ip/subnet range is invalid");
        terminateProgram(1);
    }
    else if (prefix_length == 64)
    {
        state->outbound_ip_range = 0xFFFFFFFFFFFFFFFFULL;
    }
    else
    {
        state->outbound_ip_range = (0xFFFFFFFFFFFFFFFFULL & (0x1ULL << (128 - prefix_length)));
    }
}

static void parseSubnetRange(tcpconnector_tstate_t *state, char *slash)
{
    *slash = '\0';
    int prefix_length = atoi(slash + 1);

    if (prefix_length < 0)
    {
        LOGF("TcpConnector: outbound ip/subnet range is invalid");
        terminateProgram(1);
    }

    if (state->constant_dest_addr.ip_address.type == AF_INET)
    {
        configureIpv4Range(state, prefix_length);
    }
    else if (state->constant_dest_addr.ip_address.type == AF_INET6)
    {
        configureIpv6Range(state, prefix_length);
    }
}

static void configureConstantAddress(tcpconnector_tstate_t *state)
{
    if (state->dest_addr_selected.status != kDvsConstant)
    {
        return;
    }

    char *slash = stringChr(state->dest_addr_selected.string, '/');
    if (slash != NULL)
    {
        parseSubnetRange(state, slash);
    }

    if (state->constant_dest_addr.type_ip == false)
    {
        addresscontextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.string,
                                        (uint8_t) stringLength(state->dest_addr_selected.string));
    }
    else
    {
        sockaddr_u temp;
        sockaddrSetIpAddress(&(temp), state->dest_addr_selected.string);
        sockaddrToIpAddr(&temp, &(state->constant_dest_addr.ip_address));
    }
}

static bool parseDestinationPort(tcpconnector_tstate_t *state, const cJSON *settings)
{
    state->dest_port_selected = parseDynamicNumericValueFromJsonObject(settings, "port", 2, "src_context->port", "dest_context->port");

    if (state->dest_port_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: TcpConnector->settings->port (number field) : The vaule was empty or invalid");
        return false;
    }

    if (state->dest_port_selected.status == kDvsConstant)
    {
        addresscontextSetPort(&(state->constant_dest_addr), (uint16_t) state->dest_port_selected.integer);
    }

    return true;
}

tunnel_t *tcpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcpconnector_tstate_t), sizeof(tcpconnector_lstate_t), true);
    
    initializeTunnelCallbacks(t);

    tcpconnector_tstate_t *state = tunnelGetState(t);
    const cJSON *settings = node->node_settings_json;

    if (!parseBasicSettings(state, settings))
    {
        return NULL;
    }

    if (!parseDestinationAddress(state, settings))
    {
        return NULL;
    }

    configureConstantAddress(state);

    if (!parseDestinationPort(state, settings))
    {
        return NULL;
    }

    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", kFwMarkInvalid);

    state->idle_table = idleTableCreate(getWorkerLoop(getWID()));

    return t;
}
