#include "structure.h"

#include "loggers/network_logger.h"

static void initializeTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &udpconnectorTunnelUpStreamInit;
    t->fnEstU     = &udpconnectorTunnelUpStreamEst;
    t->fnFinU     = &udpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &udpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &udpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &udpconnectorTunnelUpStreamResume;

    t->fnInitD    = &udpconnectorTunnelDownStreamInit;
    t->fnEstD     = &udpconnectorTunnelDownStreamEst;
    t->fnFinD     = &udpconnectorTunnelDownStreamFinish;
    t->fnPayloadD = &udpconnectorTunnelDownStreamPayload;
    t->fnPauseD   = &udpconnectorTunnelDownStreamPause;
    t->fnResumeD  = &udpconnectorTunnelDownStreamResume;

    t->onPrepare = &udpconnectorTunnelOnPrepair;
    t->onStart   = &udpconnectorTunnelOnStart;
    t->onDestroy = &udpconnectorTunnelDestroy;
}

static bool parseBalanceMode(udpconnector_tstate_t *state, const cJSON *settings)
{
    const cJSON *jbalance_mode = cJSON_GetObjectItemCaseSensitive(settings, "balance-mode");

    state->balance_mode = kUdpConnectorBalanceModeConnection;

    if (jbalance_mode == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(jbalance_mode) || jbalance_mode->valuestring == NULL)
    {
        LOGF("JSON Error: UdpConnector->settings->balance-mode (string field) : expected \"connection\" or \"packet\"");
        return false;
    }

    if (stringCompare(jbalance_mode->valuestring, "connection") == 0)
    {
        state->balance_mode = kUdpConnectorBalanceModeConnection;
        return true;
    }

    if (stringCompare(jbalance_mode->valuestring, "packet") == 0)
    {
        state->balance_mode = kUdpConnectorBalanceModePacket;
        return true;
    }

    LOGF("JSON Error: UdpConnector->settings->balance-mode (string field) : expected \"connection\" or \"packet\"");
    return false;
}

static bool parseDestinationWeight(const cJSON *settings, int index, uint32_t *weight)
{
    const cJSON *jweight = cJSON_GetObjectItemCaseSensitive(settings, "weight");
    if (! cJSON_IsNumber(jweight) || jweight->valueint <= 0 || jweight->valuedouble != (double) jweight->valueint)
    {
        LOGF("JSON Error: UdpConnector->settings->addresses[%d]->weight (positive integer field) : The value was empty or invalid",
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
        LOGF("JSON Error: UdpConnector->settings : Use either \"addresses\" or \"adresses\", not both");
        terminateProgram(1);
    }

    if (jaddresses != NULL)
    {
        return jaddresses;
    }

    return jadresses;
}

static bool parseAddressSettings(dynamic_value_t *dest_addr_selected, address_context_t *constant_dest_addr,
                                 const cJSON *settings, const char *error_path)
{
    *dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (dest_addr_selected->status == kDvsEmpty)
    {
        LOGF("JSON Error: %s->address (string field) : The vaule was empty or invalid", error_path);
        return false;
    }

    if (dest_addr_selected->status == kDvsConstant)
    {
        if (addressIsIp(dest_addr_selected->string))
        {
            addresscontextSetIpAddress(constant_dest_addr, dest_addr_selected->string);
        }
        else
        {
            addresscontextDomainSetConstMem(constant_dest_addr, dest_addr_selected->string,
                                            (uint8_t) stringLength(dest_addr_selected->string));
        }
    }

    return true;
}

static bool parseRandomPortRange(const char *port_str, dynamic_value_t *dest_port_selected,
                                 address_context_t *constant_dest_addr, uint16_t *random_dest_port_x,
                                 uint16_t *random_dest_port_y, const char *error_path)
{
    const char *start = port_str + 7;
    const char *comma = strchr(start, ',');
    const char *end   = strchr(start, ')');

    if (comma == NULL || end == NULL || comma >= end)
    {
        LOGF("JSON Error: %s->port: Invalid random port format, expected 'random(x,y)'", error_path);
        return false;
    }

    char   x_str[16] = {0};
    size_t x_len     = comma - start;
    if (x_len >= sizeof(x_str))
    {
        LOGF("JSON Error: %s->port: X value too long in random port range", error_path);
        return false;
    }

    stringCopyN(x_str, start, x_len);
    x_str[x_len] = '\0';

    char   y_str[16] = {0};
    size_t y_len     = end - (comma + 1);
    if (y_len >= sizeof(y_str))
    {
        LOGF("JSON Error: %s->port: Y value too long in random port range", error_path);
        return false;
    }

    stringCopyN(y_str, comma + 1, y_len);
    y_str[y_len] = '\0';

    char *x_endptr;
    char *y_endptr;
    long  x_long = strtol(x_str, &x_endptr, 10);
    long  y_long = strtol(y_str, &y_endptr, 10);

    if (*x_endptr != '\0' || *y_endptr != '\0' || x_long <= 0 || x_long > UINT16_MAX ||
        y_long <= 0 || y_long > UINT16_MAX || x_long > y_long)
    {
        LOGF("JSON Error: %s->port: Invalid random port range values or x > y", error_path);
        return false;
    }

    uint16_t x_port = (uint16_t) x_long;
    uint16_t y_port = (uint16_t) y_long;

    addresscontextSetPort(constant_dest_addr, 0);
    dest_port_selected->status = kDvsRandom;
    *random_dest_port_x        = x_port;
    *random_dest_port_y        = y_port;

    LOGD("UdpConnector: Parsed random port range [%u, %u]", x_port, y_port);
    return true;
}

static bool parsePortSource(const char *port_str, dynamic_value_t *dest_port_selected)
{
    if (stringCompare(port_str, "src_context->port") == 0)
    {
        dest_port_selected->status = kDvsFromSource;
        return true;
    }

    if (stringCompare(port_str, "dest_context->port") == 0)
    {
        dest_port_selected->status = kDvsFromDest;
        return true;
    }

    return false;
}

static bool parsePortAsNumber(const char *port_str, dynamic_value_t *dest_port_selected,
                              address_context_t *constant_dest_addr, const char *error_path)
{
    char *endptr;
    long  port_long = strtol(port_str, &endptr, 10);

    if (*endptr != '\0' || port_long <= 0 || port_long > UINT16_MAX)
    {
        LOGF("JSON Error: %s->port: Expected 'random(x,y)' format or valid port number", error_path);
        return false;
    }

    uint16_t port = (uint16_t) port_long;
    dest_port_selected->status = kDvsConstant;
    addresscontextSetPort(constant_dest_addr, port);
    return true;
}

static bool parsePortStringSettings(const char *port_str, dynamic_value_t *dest_port_selected,
                                    address_context_t *constant_dest_addr, uint16_t *random_dest_port_x,
                                    uint16_t *random_dest_port_y, const char *error_path)
{
    if (stringLength(port_str) < 1)
    {
        LOGF("JSON Error: %s->port (string | int field) : The vaule was empty or invalid", error_path);
        return false;
    }

    if (parsePortSource(port_str, dest_port_selected))
    {
        return true;
    }

    if (strncmp(port_str, "random(", 7) == 0)
    {
        return parseRandomPortRange(port_str, dest_port_selected, constant_dest_addr, random_dest_port_x,
                                    random_dest_port_y, error_path);
    }

    return parsePortAsNumber(port_str, dest_port_selected, constant_dest_addr, error_path);
}

static bool parsePortSettings(dynamic_value_t *dest_port_selected, address_context_t *constant_dest_addr,
                              uint16_t *random_dest_port_x, uint16_t *random_dest_port_y, const cJSON *settings,
                              const char *error_path)
{
    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(settings, "port");

    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {
        return parsePortStringSettings(jstr->valuestring, dest_port_selected, constant_dest_addr, random_dest_port_x,
                                       random_dest_port_y, error_path);
    }

    *dest_port_selected =
        parseDynamicNumericValueFromJsonObject(settings, "port", 3, "src_context->port", "dest_context->port",
                                              "random[x,y]");

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

static void cleanupDestinationArray(udpconnector_tstate_t *state)
{
    if (state->destinations == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < state->destinations_count; ++i)
    {
        udpconnectorDestinationDeinit(&state->destinations[i]);
    }

    memoryFree(state->destinations);
    state->destinations              = NULL;
    state->destinations_count        = 0;
    state->destinations_weight_total = 0;
}

static bool parseDestinationArray(udpconnector_tstate_t *state, const cJSON *settings)
{
    const cJSON *jaddresses = getDestinationArraySettings(settings);

    if (jaddresses == NULL)
    {
        return false;
    }

    if (! cJSON_IsArray(jaddresses) || cJSON_GetArraySize(jaddresses) <= 0)
    {
        LOGF("JSON Error: UdpConnector->settings->addresses (array field) : The value was empty or invalid");
        terminateProgram(1);
    }

    if (cJSON_GetObjectItemCaseSensitive(settings, "address") != NULL ||
        cJSON_GetObjectItemCaseSensitive(settings, "port") != NULL)
    {
        LOGF("JSON Error: UdpConnector->settings : Use either \"address\"/\"port\" or \"addresses\", not both");
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
            LOGF("JSON Error: UdpConnector->settings->addresses[%d] (object field) : The value was empty or invalid",
                 index);
            cleanupDestinationArray(state);
            terminateProgram(1);
        }

        udpconnector_destination_t *destination = &state->destinations[index];
        char                        error_path[96];
        snprintf(error_path, sizeof(error_path), "UdpConnector->settings->addresses[%d]", index);

        if (! parseAddressSettings(&destination->dest_addr_selected, &destination->constant_dest_addr, entry,
                                   error_path) ||
            ! parsePortSettings(&destination->dest_port_selected, &destination->constant_dest_addr,
                                &destination->random_dest_port_x, &destination->random_dest_port_y, entry,
                                error_path) ||
            ! parseDestinationWeight(entry, index, &destination->weight))
        {
            cleanupDestinationArray(state);
            return false;
        }

        state->destinations_weight_total += destination->weight;
        index++;
    }
    return true;
}

tunnel_t *udpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));

    initializeTunnelCallbacks(t);

    const cJSON *settings = node->node_settings_json;
    udpconnector_tstate_t *state = tunnelGetState(t);

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: UdpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    getBoolFromJsonObject(&(state->reuse_addr), settings, "reuseaddr");
    getIntFromJsonObjectOrDefault(&(state->domain_strategy), settings, "domain-strategy", 0);
    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", -1);
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->send_buffer_size, settings, "large-send-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpConnector->settings->large-send-buffer (boolean-or-positive-integer field) : The value was empty or invalid");
        return NULL;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->recv_buffer_size, settings, "large-recv-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpConnector->settings->large-recv-buffer (boolean-or-positive-integer field) : The value was empty or invalid");
        return NULL;
    }
    getStringFromJsonObject(&(state->interface_name), settings, "interface");
    getStringFromJsonObject(&(state->source_ip), settings, "source-ip");
    if (! parseBalanceMode(state, settings))
    {
        return NULL;
    }
    if (state->source_ip != NULL && ! addressIsIp(state->source_ip))
    {
        LOGF("JSON Error: UdpConnector->settings->source-ip (string field) : The value must be a valid IP address");
        memoryFree(state->source_ip);
        state->source_ip = NULL;
        return NULL;
    }

    if (getDestinationArraySettings(settings) != NULL)
    {
        if (! parseDestinationArray(state, settings))
        {
            return NULL;
        }
    }
    else
    {
        if (! parseAddressSettings(&state->dest_addr_selected, &state->constant_dest_addr, settings,
                                   "UdpConnector->settings"))
        {
            return NULL;
        }

        if (! parsePortSettings(&state->dest_port_selected, &state->constant_dest_addr, &state->random_dest_port_x,
                                &state->random_dest_port_y, settings, "UdpConnector->settings"))
        {
            return NULL;
        }
    }
    state->idle_table = idleTableCreate(getWorkerLoop(getWID()));

    return t;
}
