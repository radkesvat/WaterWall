#include "structure.h"

#include "loggers/network_logger.h"

static void failInvalidPortValue(const char *field_name, int index)
{
    if (index >= 0)
    {
        LOGF("JSON Error: TcpListener->settings->%s (array of positive-integer ports) index %d : The data was empty "
             "or invalid",
             field_name,
             index);
    }
    else
    {
        LOGF("JSON Error: TcpListener->settings->%s (positive-integer port field) : The data was empty or invalid",
             field_name);
    }
    terminateProgram(1);
}

static uint16_t parsePortNumber(const cJSON *port_json, const char *field_name, int index)
{
    if (! cJSON_IsNumber(port_json) || port_json->valuedouble != (double) port_json->valueint ||
        port_json->valueint <= 0 || port_json->valueint > UINT16_MAX)
    {
        failInvalidPortValue(field_name, index);
    }

    return (uint16_t) port_json->valueint;
}

static bool listenerPortListContains(const vec_listener_port_t *ports, uint16_t port)
{
    for (isize i = 0; i < vec_listener_port_t_size(ports); ++i)
    {
        if (*vec_listener_port_t_at(ports, i) == port)
        {
            return true;
        }
    }
    return false;
}

static void parseSinglePort(tcplistener_tstate_t *state, const cJSON *port_json)
{
    uint16_t port          = parsePortNumber(port_json, "port", -1);
    state->listen_port_min = port;
    state->listen_port_max = port;
}

static void addPortListEntry(tcplistener_tstate_t *state, socket_filter_option_t *filter_opt, uint16_t port)
{
    if (! listenerPortListContains(&filter_opt->ports, port))
    {
        vec_listener_port_t_push(&filter_opt->ports, port);
    }

    if (state->listen_port_min == 0 || port < state->listen_port_min)
    {
        state->listen_port_min = port;
    }
    if (port > state->listen_port_max)
    {
        state->listen_port_max = port;
    }
}

static void parsePortList(tcplistener_tstate_t *state, socket_filter_option_t *filter_opt, const cJSON *port_json)
{
    if (! cJSON_IsArray(port_json) || cJSON_GetArraySize(port_json) <= 0)
    {
        failInvalidPortValue("port", -1);
    }

    int          index     = 0;
    const cJSON *port_item = NULL;
    cJSON_ArrayForEach(port_item, port_json)
    {
        uint16_t port = parsePortNumber(port_item, "port", index);
        addPortListEntry(state, filter_opt, port);
        index++;
    }
}

static void parsePortRange(tcplistener_tstate_t *state, const cJSON *port_range_json)
{
    if (! cJSON_IsArray(port_range_json) || cJSON_GetArraySize(port_range_json) != 2)
    {
        failInvalidPortValue("port-range", -1);
    }

    const cJSON *port_min_json = cJSON_GetArrayItem(port_range_json, 0);
    const cJSON *port_max_json = cJSON_GetArrayItem(port_range_json, 1);
    uint16_t     port_min      = parsePortNumber(port_min_json, "port-range", 0);
    uint16_t     port_max      = parsePortNumber(port_max_json, "port-range", 1);

    if (port_min > port_max)
    {
        LOGF("JSON Error: TcpListener->settings->port-range (array[2] field) : min port must be lower than or equal "
             "to max port");
        terminateProgram(1);
    }

    state->listen_port_min = port_min;
    state->listen_port_max = port_max;
}

static void parsePortSection(tcplistener_tstate_t *state, socket_filter_option_t *filter_opt, const cJSON *settings)
{
    const cJSON *port_json       = cJSON_GetObjectItemCaseSensitive(settings, "port");
    const cJSON *port_range_json = cJSON_GetObjectItemCaseSensitive(settings, "port-range");

    if (port_json != NULL && port_range_json != NULL)
    {
        LOGF("JSON Error: TcpListener->settings : use either \"port\" or \"port-range\", not both");
        terminateProgram(1);
    }

    if (port_range_json != NULL)
    {
        parsePortRange(state, port_range_json);
        return;
    }

    if (cJSON_IsNumber(port_json))
    {
        parseSinglePort(state, port_json);
        return;
    }

    if (cJSON_IsArray(port_json))
    {
        parsePortList(state, filter_opt, port_json);
        return;
    }

    LOGF("JSON Error: TcpListener->settings->port (positive-integer port or array of positive-integer ports field) : "
         "The data was empty or invalid");
    terminateProgram(1);
}

static bool hasMultiplePorts(const tcplistener_tstate_t *state, const socket_filter_option_t *filter_opt)
{
    if (vec_listener_port_t_size(&filter_opt->ports) > 1)
    {
        return true;
    }
    return state->listen_port_min != state->listen_port_max;
}

static void initializeTunnelCallbacks(tunnel_t *t)
{
    t->fnInitD    = &tcplistenerTunnelDownStreamInit;
    t->fnEstD     = &tcplistenerTunnelDownStreamEst;
    t->fnFinD     = &tcplistenerTunnelDownStreamFinish;
    t->fnPayloadD = &tcplistenerTunnelDownStreamPayload;
    t->fnPauseD   = &tcplistenerTunnelDownStreamPause;
    t->fnResumeD  = &tcplistenerTunnelDownStreamResume;

    t->onPrepare = &tcplistenerTunnelOnPrepair;
    t->onStart   = &tcplistenerTunnelOnStart;
    t->onStop    = &tcplistenerTunnelOnStop;
    t->onWorkerStop = &tcplistenerTunnelOnWorkerStop;
    t->onDestroy = &tcplistenerTunnelDestroy;
}

static bool parseBasicSettings(tcplistener_tstate_t *state, const cJSON *settings)
{
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpListener->settings (object field) : The object was empty or invalid");
        return false;
    }

    getBoolFromJsonObject(&(state->option_tcp_no_delay), settings, "nodelay");
    state->send_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-send-buffer") != NULL;
    state->recv_buffer_size_set = cJSON_GetObjectItemCaseSensitive(settings, "large-recv-buffer") != NULL;
    if (! getPositiveIntFromJsonObjectOrBoolDefault(
            &state->send_buffer_size, settings, "large-send-buffer", kDefaultLargeSocketBufferSize, 0))
    {
        LOGF("JSON Error: TcpListener->settings->large-send-buffer (boolean-or-positive-integer field) : The value was "
             "empty or invalid");
        return false;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(
            &state->recv_buffer_size, settings, "large-recv-buffer", kDefaultLargeSocketBufferSize, 0))
    {
        LOGF("JSON Error: TcpListener->settings->large-recv-buffer (boolean-or-positive-integer field) : The value was "
             "empty or invalid");
        return false;
    }

    if (! getStringFromJsonObject(&(state->listen_address), settings, "address"))
    {
        LOGF("JSON Error: TcpListener->settings->address (string field) : The data was empty or invalid");
        return false;
    }

    return true;
}

static void configureMultiportBackend(socket_filter_option_t *filter_opt, tcplistener_tstate_t *state,
                                      const cJSON *settings)
{
    filter_opt->multiport_backend = kMultiportBackendNone;

    if (! hasMultiplePorts(state, filter_opt))
    {
        return;
    }

    if (vec_listener_port_t_size(&filter_opt->ports) > 0)
    {
        filter_opt->multiport_backend = kMultiportBackendSockets;
        return;
    }

    if (state->listen_port_max != 0)
    {
        filter_opt->multiport_backend = kMultiportBackendDefault;
        dynamic_value_t dy_mb =
            parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
        if (dy_mb.status == kDvsFirstOption)
        {
            filter_opt->multiport_backend = kMultiportBackendIptables;
        }
        if (dy_mb.status == kDvsSecondOption)
        {
            filter_opt->multiport_backend = kMultiportBackendSockets;
        }
    }
}

static void parseIpMaskListEntry(const cJSON *list_item, vec_ipmask_t *target_list, const char *list_name, int index)
{
    char    *ip_str = NULL;
    ipmask_t ipmask;

    if (! getStringFromJson(&(ip_str), list_item) || ! verifyIPCdir(ip_str))
    {
        LOGF("JSON Error: TcpListener->settings->%s (array of strings field) index %d : The data was empty or invalid",
             list_name,
             index);
        terminateProgram(1);
    }

    int parse_result = parseIPWithSubnetMask(ip_str, &(ipmask.ip), &(ipmask.mask));
    if (parse_result == -1)
    {
        LOGF("TcpListener: stopping due to %s address [%d] \"%s\" parse failure", list_name, index, ip_str);
        terminateProgram(1);
    }

    vec_ipmask_t_push(target_list, ipmask);
    memoryFree(ip_str);
}

static void parseIpMaskList(const cJSON *settings, const char *list_name, vec_ipmask_t *target_list)
{
    const cJSON *list = cJSON_GetObjectItemCaseSensitive(settings, list_name);
    if (! cJSON_IsArray(list))
    {
        return;
    }

    int len = cJSON_GetArraySize(list);
    if (len <= 0)
    {
        return;
    }

    int          i         = 0;
    const cJSON *list_item = NULL;
    cJSON_ArrayForEach(list_item, list)
    {
        parseIpMaskListEntry(list_item, target_list, list_name, i);
        i++;
    }
}

static void setupFilterOptions(socket_filter_option_t *filter_opt, tcplistener_tstate_t *state, const cJSON *settings)
{
    socketfilteroptionInit(filter_opt);
    filter_opt->no_delay         = state->option_tcp_no_delay;
    filter_opt->send_buffer_size = state->send_buffer_size;
    filter_opt->recv_buffer_size = state->recv_buffer_size;

    getStringFromJsonObject(&(filter_opt->interface_name), settings, "interface");
    getStringFromJsonObject(&(filter_opt->balance_group_name), settings, "balance-group");
    getIntFromJsonObject((int *) &(filter_opt->balance_group_interval), settings, "balance-interval");
    getIntFromJsonObjectOrDefault(&(filter_opt->fwmark), settings, "fwmark", -1);

    parsePortSection(state, filter_opt, settings);
    configureMultiportBackend(filter_opt, state, settings);
    parseIpMaskList(settings, "whitelist", &filter_opt->white_list);
    parseIpMaskList(settings, "blacklist", &filter_opt->black_list);

    filter_opt->host     = state->listen_address;
    filter_opt->port_min = state->listen_port_min;
    filter_opt->port_max = state->listen_port_max;
    filter_opt->protocol = IPPROTO_TCP;
}

tunnel_t *tcplistenerTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcplistener_tstate_t), sizeof(tcplistener_lstate_t), false);

    initializeTunnelCallbacks(t);

    tcplistener_tstate_t *state    = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;

    if (! parseBasicSettings(state, settings))
    {
        return NULL;
    }

    socket_filter_option_t filter_opt;
    setupFilterOptions(&filter_opt, state, settings);

    state->idle_tables = memoryAllocate(sizeof(*state->idle_tables) * getWorkersCount());
    memorySet(state->idle_tables, 0, sizeof(*state->idle_tables) * getWorkersCount());
    atomicStoreRelaxed(&state->stopping, false);

    socketacceptorRegister(t, filter_opt, tcplistenerOnInboundConnected);

    return t;
}
