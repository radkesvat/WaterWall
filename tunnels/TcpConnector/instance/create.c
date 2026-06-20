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

    t->onPrepare    = &tcpconnectorTunnelOnPrepair;
    t->onStart      = &tcpconnectorTunnelOnStart;
    t->onStop       = &tcpconnectorTunnelOnStop;
    t->onWorkerStop = &tcpconnectorTunnelOnWorkerStop;
    t->onDestroy    = &tcpconnectorTunnelDestroy;
}

static bool parseBasicSettings(tcpconnector_tstate_t *state, const cJSON *settings)
{
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpConnector->settings (object field) : The object was empty or invalid");
        return false;
    }

    getBoolFromJsonObjectOrDefault(&(state->option_tcp_no_delay), settings, "nodelay", true);
    getBoolFromJsonObjectOrDefault(&(state->option_tcp_fast_open), settings, "fastopen", false);
    getBoolFromJsonObjectOrDefault(&(state->option_reuse_addr), settings, "reuseaddr", false);
    enum domain_strategy domain_strategy = GSTATE.domain_strategy;
    if (! getDomainStrategyFromJsonObjectOrDefault(
            &domain_strategy, settings, "domain-strategy", GSTATE.domain_strategy))
    {
        LOGF("JSON Error: TcpConnector->settings->domain-strategy (string or integer field) : The value was invalid");
        return false;
    }
    state->domain_strategy = domain_strategy;
    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", kFwMarkInvalid);
    state->send_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-send-buffer") != NULL;
    state->recv_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-recv-buffer") != NULL;
    if (! getPositiveIntFromJsonObjectOrBoolDefault(
            &state->send_buffer_size, settings, "large-send-buffer", kDefaultLargeSocketBufferSize, 0))
    {
        LOGF("JSON Error: TcpConnector->settings->large-send-buffer (boolean-or-positive-integer field) : The value "
             "was empty or invalid");
        return false;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(
            &state->recv_buffer_size, settings, "large-recv-buffer", kDefaultLargeSocketBufferSize, 0))
    {
        LOGF("JSON Error: TcpConnector->settings->large-recv-buffer (boolean-or-positive-integer field) : The value "
             "was empty or invalid");
        return false;
    }
    getStringFromJsonObject(&(state->interface_name), settings, "interface");
    getStringFromJsonObject(&(state->source_ip), settings, "source-ip");
    if (state->source_ip != NULL && ! addressIsIp(state->source_ip))
    {
        LOGF("JSON Error: TcpConnector->settings->source-ip (string field) : The value must be a valid IP address");
        memoryFree(state->source_ip);
        state->source_ip = NULL;
        return false;
    }

    return true;
}

static bool parseDestinationStringOption(char **dest, const cJSON *settings, const char *key, const char *default_value,
                                         const char *error_path)
{
    assert(*dest == NULL);

    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (jstr == NULL)
    {
        *dest = stringDuplicate(default_value);
        return default_value == NULL || *dest != NULL;
    }

    if (cJSON_IsNull(jstr))
    {
        return true;
    }

    if (! cJSON_IsString(jstr) || jstr->valuestring == NULL)
    {
        LOGF("JSON Error: %s->%s (string or null field) : The value was invalid", error_path, key);
        return false;
    }

    *dest = stringDuplicate(jstr->valuestring);
    return *dest != NULL;
}

static bool parseDestinationSocketOptions(tcpconnector_destination_t *destination, const tcpconnector_tstate_t *state,
                                          const cJSON *settings, const char *error_path)
{
    getBoolFromJsonObjectOrDefault(&destination->option_tcp_no_delay, settings, "nodelay", state->option_tcp_no_delay);
    getBoolFromJsonObjectOrDefault(
        &destination->option_tcp_fast_open, settings, "fastopen", state->option_tcp_fast_open);
    getBoolFromJsonObjectOrDefault(&destination->option_reuse_addr, settings, "reuseaddr", state->option_reuse_addr);
    getIntFromJsonObjectOrDefault(&destination->fwmark, settings, "fwmark", state->fwmark);
    enum domain_strategy domain_strategy = (enum domain_strategy) state->domain_strategy;
    if (! getDomainStrategyFromJsonObjectOrDefault(
            &domain_strategy, settings, "domain-strategy", (enum domain_strategy) state->domain_strategy))
    {
        LOGF("JSON Error: %s->domain-strategy (string or integer field) : The value was invalid", error_path);
        return false;
    }
    destination->domain_strategy      = domain_strategy;
    destination->send_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-send-buffer") != NULL;
    destination->recv_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-recv-buffer") != NULL;
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&destination->send_buffer_size,
                                                    settings,
                                                    "large-send-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    state->send_buffer_size))
    {
        LOGF("JSON Error: %s->large-send-buffer (boolean-or-positive-integer field) : The value was empty or invalid",
             error_path);
        return false;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&destination->recv_buffer_size,
                                                    settings,
                                                    "large-recv-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    state->recv_buffer_size))
    {
        LOGF("JSON Error: %s->large-recv-buffer (boolean-or-positive-integer field) : The value was empty or invalid",
             error_path);
        return false;
    }

    if (! parseDestinationStringOption(
            &destination->interface_name, settings, "interface", state->interface_name, error_path) ||
        ! parseDestinationStringOption(&destination->source_ip, settings, "source-ip", state->source_ip, error_path))
    {
        return false;
    }

    if (destination->source_ip != NULL && ! addressIsIp(destination->source_ip))
    {
        LOGF("JSON Error: %s->source-ip (string field) : The value must be a valid IP address", error_path);
        return false;
    }

    return true;
}

static bool parseDestinationWeight(const cJSON *settings, int index, uint32_t *weight)
{
    const cJSON *jweight = cJSON_GetObjectItemCaseSensitive(settings, "weight");
    if (! cJSON_IsNumber(jweight) || jweight->valueint <= 0 || jweight->valuedouble != (double) jweight->valueint)
    {
        LOGF("JSON Error: TcpConnector->settings->addresses[%d]->weight (positive integer field) : The value was empty "
             "or invalid",
             index);
        return false;
    }

    *weight = (uint32_t) jweight->valueint;
    return true;
}

static const cJSON *getDestinationArraySettings(const cJSON *settings)
{
    const cJSON *jaddresses = cJSON_GetObjectItemCaseSensitive(settings, "addresses");
    const cJSON *jadresses  = cJSON_GetObjectItemCaseSensitive(settings, "adresses");

    if (jaddresses != NULL && jadresses != NULL)
    {
        LOGF("JSON Error: TcpConnector->settings : Use either \"addresses\" or \"adresses\", not both");
        terminateProgram(1);
    }

    if (jaddresses != NULL)
    {
        return jaddresses;
    }

    return jadresses;
}

static void configureIpv4RangeValue(uint64_t *outbound_ip_range, int prefix_length)
{
    if (prefix_length > 32)
    {
        LOGF("TcpConnector: outbound ip/subnet range is invalid");
        terminateProgram(1);
    }
    else if (prefix_length == 32)
    {
        *outbound_ip_range = 0;
    }
    else
    {
        *outbound_ip_range = (0xFFFFFFFFULL & (0x1ULL << (32 - prefix_length)));
    }
}

static void configureIpv6RangeValue(uint64_t *outbound_ip_range, int prefix_length)
{
    if (64 > prefix_length)
    {
        LOGF("TcpConnector: outbound ip/subnet range is invalid");
        terminateProgram(1);
    }
    else if (prefix_length == 64)
    {
        *outbound_ip_range = 0xFFFFFFFFFFFFFFFFULL;
    }
    else
    {
        *outbound_ip_range = (0xFFFFFFFFFFFFFFFFULL & (0x1ULL << (128 - prefix_length)));
    }
}

static bool parseDestinationAddress(dynamic_value_t *dest_addr_selected, address_context_t *constant_dest_addr,
                                    uint64_t *outbound_ip_range, const cJSON *settings, const char *error_path)
{
    *dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (dest_addr_selected->status == kDvsEmpty)
    {
        LOGF("JSON Error: %s->address (string field) : The vaule was empty or invalid", error_path);
        return false;
    }

    *outbound_ip_range = 0;

    if (dest_addr_selected->status != kDvsConstant)
    {
        return true;
    }

    char *address_value = dest_addr_selected->string;
    char *slash         = stringChr(address_value, '/');
    if (slash != NULL)
    {
        *slash = '\0';
    }

    if (addressIsIp(address_value))
    {
        if (! addresscontextSetIpAddress(constant_dest_addr, address_value))
        {
            LOGF("JSON Error: %s->address (string field) : The vaule was empty or invalid", error_path);
            return false;
        }

        if (slash != NULL)
        {
            int prefix_length = atoi(slash + 1);

            if (prefix_length < 0)
            {
                LOGF("TcpConnector: outbound ip/subnet range is invalid");
                terminateProgram(1);
            }

            if (constant_dest_addr->ip_address.type == IPADDR_TYPE_V4)
            {
                configureIpv4RangeValue(outbound_ip_range, prefix_length);
            }
            else if (constant_dest_addr->ip_address.type == IPADDR_TYPE_V6)
            {
                configureIpv6RangeValue(outbound_ip_range, prefix_length);
            }
        }
    }
    else
    {
        if (slash != NULL)
        {
            LOGF("JSON Error: %s->address (string field) : CIDR suffix is only valid for IP addresses", error_path);
            return false;
        }

        addresscontextDomainSetConstMem(constant_dest_addr, address_value, (uint8_t) stringLength(address_value));
    }

    return true;
}

static bool parseDestinationPort(dynamic_value_t *dest_port_selected, address_context_t *constant_dest_addr,
                                 const cJSON *settings, const char *error_path)
{
    *dest_port_selected =
        parseDynamicNumericValueFromJsonObject(settings, "port", 2, "src_context->port", "dest_context->port");

    if (dest_port_selected->status == kDvsEmpty)
    {
        LOGF("JSON Error: %s->port (number field) : The vaule was empty or invalid", error_path);
        return false;
    }

    if (dest_port_selected->status == kDvsConstant)
    {
        if (dest_port_selected->integer == 0 || dest_port_selected->integer > UINT16_MAX)
        {
            LOGF("JSON Error: %s->port (number field) : expected a valid port number", error_path);
            return false;
        }
        addresscontextSetPort(constant_dest_addr, (uint16_t) dest_port_selected->integer);
    }

    return true;
}

static void cleanupDestinationArray(tcpconnector_tstate_t *state)
{
    if (state->destinations == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < state->destinations_count; ++i)
    {
        tcpconnectorDestinationDeinit(&state->destinations[i]);
    }

    memoryFree(state->destinations);
    state->destinations              = NULL;
    state->destinations_count        = 0;
    state->destinations_weight_total = 0;
}

static bool parseDestinationArray(tcpconnector_tstate_t *state, const cJSON *settings)
{
    const cJSON *jaddresses = getDestinationArraySettings(settings);

    if (jaddresses == NULL)
    {
        return false;
    }

    if (! cJSON_IsArray(jaddresses) || cJSON_GetArraySize(jaddresses) <= 0)
    {
        LOGF("JSON Error: TcpConnector->settings->addresses (array field) : The value was empty or invalid");
        terminateProgram(1);
    }

    if (cJSON_GetObjectItemCaseSensitive(settings, "address") != NULL ||
        cJSON_GetObjectItemCaseSensitive(settings, "port") != NULL)
    {
        LOGF("JSON Error: TcpConnector->settings : Use either \"address\"/\"port\" or \"addresses\", not both");
        terminateProgram(1);
    }

    const int destination_count = cJSON_GetArraySize(jaddresses);
    state->destinations         = memoryAllocateZero(sizeof(*state->destinations) * (size_t) destination_count);
    state->destinations_count   = (uint32_t) destination_count;

    int          index = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, jaddresses)
    {
        if (! cJSON_IsObject(entry) || entry->child == NULL)
        {
            LOGF("JSON Error: TcpConnector->settings->addresses[%d] (object field) : The value was empty or invalid",
                 index);
            cleanupDestinationArray(state);
            terminateProgram(1);
        }

        tcpconnector_destination_t *destination = &state->destinations[index];
        char                        error_path[96];
        snprintf(error_path, sizeof(error_path), "TcpConnector->settings->addresses[%d]", index);

        if (! parseDestinationAddress(&destination->dest_addr_selected,
                                      &destination->constant_dest_addr,
                                      &destination->outbound_ip_range,
                                      entry,
                                      error_path) ||
            ! parseDestinationPort(
                &destination->dest_port_selected, &destination->constant_dest_addr, entry, error_path) ||
            ! parseDestinationWeight(entry, index, &destination->weight) ||
            ! parseDestinationSocketOptions(destination, state, entry, error_path))
        {
            cleanupDestinationArray(state);
            return false;
        }

        state->destinations_weight_total += destination->weight;
        index++;
    }
    return true;
}

tunnel_t *tcpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcpconnector_tstate_t), sizeof(tcpconnector_lstate_t), true);

    initializeTunnelCallbacks(t);

    tcpconnector_tstate_t *state    = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    if (! parseBasicSettings(state, settings))
    {
        tcpconnectorTunnelDestroy(t);
        return NULL;
    }

    if (getDestinationArraySettings(settings) != NULL)
    {
        if (! parseDestinationArray(state, settings))
        {
            tcpconnectorTunnelDestroy(t);
            return NULL;
        }
    }
    else
    {
        if (! parseDestinationAddress(&state->dest_addr_selected,
                                      &state->constant_dest_addr,
                                      &state->outbound_ip_range,
                                      settings,
                                      "TcpConnector->settings"))
        {
            tcpconnectorTunnelDestroy(t);
            return NULL;
        }

        if (! parseDestinationPort(
                &state->dest_port_selected, &state->constant_dest_addr, settings, "TcpConnector->settings"))
        {
            tcpconnectorTunnelDestroy(t);
            return NULL;
        }
    }

    state->idle_tables = memoryAllocate(sizeof(*state->idle_tables) * getWorkersCount());
    memorySet(state->idle_tables, 0, sizeof(*state->idle_tables) * getWorkersCount());

    return t;
}
