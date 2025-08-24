#include "structure.h"

#include "loggers/network_logger.h"

static void parseSinglePort(tcplistener_tstate_t *state, const cJSON *port_json)
{
    state->listen_port_min = (uint16_t) port_json->valuedouble;
    state->listen_port_max = (uint16_t) port_json->valuedouble;
}

static void parsePortRange(tcplistener_tstate_t *state, const cJSON *port_json)
{
    const cJSON *port_minmax;
    int i = 0;
    cJSON_ArrayForEach(port_minmax, port_json)
    {
        if (!(cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
        {
            LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid");
            terminateProgram(1);
        }
        if (i == 0)
        {
            state->listen_port_min = (uint16_t) port_minmax->valuedouble;
        }
        else if (i == 1)
        {
            state->listen_port_max = (uint16_t) port_minmax->valuedouble;
        }
        i++;
    }
}

static void parsePortSection(tcplistener_tstate_t *state, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if (cJSON_IsNumber(port_json) && (port_json->valuedouble != 0))
    {
        parseSinglePort(state, port_json);
    }
    else if (cJSON_IsArray(port_json) && cJSON_GetArraySize(port_json) == 2)
    {
        parsePortRange(state, port_json);
    }
    else
    {
        LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid");
        terminateProgram(1);
    }
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
    t->onDestroy = &tcplistenerTunnelDestroy;
}

static bool parseBasicSettings(tcplistener_tstate_t *state, const cJSON *settings)
{
    if (!checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpListener->settings (object field) : The object was empty or invalid");
        return false;
    }

    getBoolFromJsonObject(&(state->option_tcp_no_delay), settings, "nodelay");

    if (!getStringFromJsonObject(&(state->listen_address), settings, "address"))
    {
        LOGF("JSON Error: TcpListener->settings->address (string field) : The data was empty or invalid");
        return false;
    }

    return true;
}

static void configureMultiportBackend(socket_filter_option_t *filter_opt, tcplistener_tstate_t *state, const cJSON *settings)
{
    filter_opt->multiport_backend = kMultiportBackendNone;
    
    if (state->listen_port_max != 0)
    {
        filter_opt->multiport_backend = kMultiportBackendDefault;
        dynamic_value_t dy_mb = parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
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

static void parseWhitelistEntry(const cJSON *list_item, socket_filter_option_t *filter_opt, int index)
{
    char *ip_str = NULL;
    ipmask_t ipmask;

    if (!getStringFromJson(&(ip_str), list_item) || !verifyIPCdir(ip_str))
    {
        LOGF("JSON Error: TcpListener->settings->whitelist (array of strings field) index %d : The data was empty or invalid", index);
        terminateProgram(1);
    }

    int parse_result = parseIPWithSubnetMask(ip_str, &(ipmask.ip), &(ipmask.mask));
    if (parse_result == -1)
    {
        LOGF("TcpListener: stopping due to whitelist address [%d] \"%s\" parse failure", index, ip_str);
        terminateProgram(1);
    }
    
    vec_ipmask_t_push(&filter_opt->white_list, ipmask);
}

static void parseWhitelist(socket_filter_option_t *filter_opt, const cJSON *settings)
{
    const cJSON *wlist = cJSON_GetObjectItemCaseSensitive(settings, "whitelist");
    if (!cJSON_IsArray(wlist))
    {
        return;
    }

    int len = cJSON_GetArraySize(wlist);
    if (len <= 0)
    {
        return;
    }

    int i = 0;
    const cJSON *list_item = NULL;
    cJSON_ArrayForEach(list_item, wlist)
    {
        parseWhitelistEntry(list_item, filter_opt, i);
        i++;
    }
}

static void setupFilterOptions(socket_filter_option_t *filter_opt, tcplistener_tstate_t *state, const cJSON *settings)
{
    socketfilteroptionInit(filter_opt);
    filter_opt->no_delay = state->option_tcp_no_delay;

    getStringFromJsonObject(&(filter_opt->interface_name), settings, "interface");
    getStringFromJsonObject(&(filter_opt->balance_group_name), settings, "balance-group");
    getIntFromJsonObject((int *) &(filter_opt->balance_group_interval), settings, "balance-interval");

    parsePortSection(state, settings);
    configureMultiportBackend(filter_opt, state, settings);
    parseWhitelist(filter_opt, settings);

    filter_opt->host = state->listen_address;
    filter_opt->port_min = state->listen_port_min;
    filter_opt->port_max = state->listen_port_max;
    filter_opt->protocol = IPPROTO_TCP;
}

tunnel_t *tcplistenerTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcplistener_tstate_t), sizeof(tcplistener_lstate_t), false);
    
    initializeTunnelCallbacks(t);

    tcplistener_tstate_t *state = tunnelGetState(t);
    const cJSON *settings = node->node_settings_json;

    if (!parseBasicSettings(state, settings))
    {
        return NULL;
    }

    socket_filter_option_t filter_opt;
    setupFilterOptions(&filter_opt, state, settings);
    
    state->idle_table = idleTableCreate(getWorkerLoop(getWID()));
    socketacceptorRegister(t, filter_opt, tcplistenerOnInboundConnected);

    return t;
}
