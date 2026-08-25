#include "structure.h"

#include "loggers/network_logger.h"

static void failInvalidPortValue(const char *field_name, int index)
{
    if (index >= 0)
    {
        LOGF("JSON Error: UdpListener->settings->%s (array of positive-integer ports) index %d : The data was empty "
             "or invalid",
             field_name,
             index);
    }
    else
    {
        LOGF("JSON Error: UdpListener->settings->%s (positive-integer port field) : The data was empty or invalid",
             field_name);
    }
    startupFailureRecord(1);
    return;
}

static uint16_t parsePortNumber(const cJSON *port_json, const char *field_name, int index)
{
    int64_t val = 0;
    if (! jsonGetIntegerInRange(port_json, 1, UINT16_MAX, &val))
    {
        failInvalidPortValue(field_name, index);
    }

    return (uint16_t) val;
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

static void parseSinglePort(udplistener_tstate_t *state, const cJSON *port_json)
{
    uint16_t port          = parsePortNumber(port_json, "port", -1);
    state->listen_port_min = port;
    state->listen_port_max = port;
}

static void addPortListEntry(udplistener_tstate_t *state, socket_filter_option_t *filter_opt, uint16_t port)
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

static void parsePortList(udplistener_tstate_t *state, socket_filter_option_t *filter_opt, const cJSON *port_json)
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

static void parsePortRange(udplistener_tstate_t *state, const cJSON *port_range_json)
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
        LOGF("JSON Error: UdpListener->settings->port-range (array[2] field) : min port must be lower than or equal "
             "to max port");
        startupFailureRecord(1);
        return;
    }

    state->listen_port_min = port_min;
    state->listen_port_max = port_max;
}

static void parsePortSection(udplistener_tstate_t *state, socket_filter_option_t *filter_opt, const cJSON *settings)
{
    const cJSON *port_json       = cJSON_GetObjectItemCaseSensitive(settings, "port");
    const cJSON *port_range_json = cJSON_GetObjectItemCaseSensitive(settings, "port-range");

    if (port_json != NULL && port_range_json != NULL)
    {
        LOGF("JSON Error: UdpListener->settings : use either \"port\" or \"port-range\", not both");
        startupFailureRecord(1);
        return;
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

    LOGF("JSON Error: UdpListener->settings->port (positive-integer port or array of positive-integer ports field) : "
         "The data was empty or invalid");
    startupFailureRecord(1);
    return;
}

static bool hasMultiplePorts(const udplistener_tstate_t *state, const socket_filter_option_t *filter_opt)
{
    if (vec_listener_port_t_size(&filter_opt->ports) > 1)
    {
        return true;
    }
    return state->listen_port_min != state->listen_port_max;
}

static void setupTunnelCallbacks(tunnel_t *t)
{
    t->fnInitD    = &udplistenerTunnelDownStreamInit;
    t->fnEstD     = &udplistenerTunnelDownStreamEst;
    t->fnFinD     = &udplistenerTunnelDownStreamFinish;
    t->fnPayloadD = &udplistenerTunnelDownStreamPayload;
    t->fnPauseD   = &udplistenerTunnelDownStreamPause;
    t->fnResumeD  = &udplistenerTunnelDownStreamResume;

    t->onPrepare        = &udplistenerTunnelOnPrepair;
    t->onStart          = &udplistenerTunnelOnStart;
    t->onQuiesceRequest = &udplistenerTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = &udplistenerTunnelOnWorkerQuiesce;
    t->onWorkerStop     = &udplistenerTunnelOnWorkerStop;
    t->onStop           = &udplistenerTunnelOnStop;
    t->onDestroy        = &udplistenerTunnelDestroy;
}

static bool validateAndSetAddress(udplistener_tstate_t *state, const cJSON *settings)
{
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: UdpListener->settings (object field) : The object was empty or invalid");
        return false;
    }

    if (! getStringFromJsonObject(&(state->listen_address), settings, "address"))
    {
        LOGF("JSON Error: UdpListener->settings->address (string field) : The data was empty or invalid");
        return false;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->send_buffer_size,
                                                    settings,
                                                    "large-send-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpListener->settings->large-send-buffer (boolean-or-positive-integer field) : The value was "
             "empty or invalid");
        return false;
    }
    if (! getPositiveIntFromJsonObjectOrBoolDefault(&state->recv_buffer_size,
                                                    settings,
                                                    "large-recv-buffer",
                                                    kDefaultLargeSocketBufferSize,
                                                    kDefaultLargeSocketBufferSize))
    {
        LOGF("JSON Error: UdpListener->settings->large-recv-buffer (boolean-or-positive-integer field) : The value was "
             "empty or invalid");
        return false;
    }

    return true;
}

static void configureMultiportBackend(socket_filter_option_t *filter_opt, udplistener_tstate_t *state,
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
        else if (dy_mb.status == kDvsSecondOption)
        {
            filter_opt->multiport_backend = kMultiportBackendSockets;
        }
    }
}

static void parseIpMaskListEntry(const cJSON *list_item, vec_ipmask_t *target_list, const char *list_name, int index)
{
    char    *ip_str = NULL;
    ipmask_t ipmask;

    if (! getStringFromJson(&ip_str, list_item) || ! verifyIPCdir(ip_str))
    {
        LOGF("JSON Error: UdpListener->settings->%s (array of strings field) index %d : The data was empty or invalid",
             list_name,
             index);
        memoryFree(ip_str);
        startupFailureRecord(1);
        return;
    }

    int parse_result = parseIPWithSubnetMask(ip_str, &(ipmask.ip), &(ipmask.mask));
    if (parse_result != 4 && parse_result != 6)
    {
        LOGF("UdpListener: stopping due to %s address [%d] \"%s\" parse failure", list_name, index, ip_str);
        memoryFree(ip_str);
        startupFailureRecord(1);
        return;
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

static bool copyIpMaskList(vec_ipmask_t *dst, const vec_ipmask_t *src)
{
    /* socketfilteroptionInit() already gave both destination vectors owned
     * backing storage. Preserve it so socketfilteroptionDeInit() can release
     * the same allocations exactly once. */
    if (dst == src)
    {
        return true;
    }

    const isize_t initial_size = vec_ipmask_t_size(dst);
    const isize_t source_size  = vec_ipmask_t_size(src);

    if (source_size > ISIZE_MAX - initial_size)
    {
        return false;
    }
    const isize_t needed = initial_size + source_size;

    if (needed > vec_ipmask_t_capacity(dst))
    {
#ifdef UDPLISTENER_CREATE_TEST_HOOKS
        if (udplistenerTestFailAclCopyReserve())
        {
            return false;
        }
#endif

        if (! vec_ipmask_t_reserve(dst, needed) || vec_ipmask_t_capacity(dst) < needed)
        {
            return false;
        }
    }

    for (isize i = 0; i < vec_ipmask_t_size(src); ++i)
    {
        if (UNLIKELY(vec_ipmask_t_push(dst, *vec_ipmask_t_at(src, i)) == NULL))
        {
            /* ipmask_t has no owned subobjects. Keep this helper atomic for
             * callers that choose to retry after a transient allocation
             * failure, while the constructor below still deinitializes the
             * complete unpublished option before returning NULL. */
            dst->size = initial_size;
            return false;
        }
    }

    return true;
}

#ifdef UDPLISTENER_CREATE_TEST_HOOKS
bool udplistenerTestCopyIpMaskList(vec_ipmask_t *dst, const vec_ipmask_t *src)
{
    return copyIpMaskList(dst, src);
}
#endif

static bool setupFilterOptions(socket_filter_option_t *filter_opt, udplistener_tstate_t *state, const cJSON *settings)
{
    socketfilteroptionInit(filter_opt);
    filter_opt->send_buffer_size = state->send_buffer_size;
    filter_opt->recv_buffer_size = state->recv_buffer_size;

    if (state->interface_name != NULL)
    {
        filter_opt->interface_name = stringDuplicate(state->interface_name);
    }
    getStringFromJsonObject(&(filter_opt->balance_group_name), settings, "balance-group");
    getIntFromJsonObject((int *) &(filter_opt->balance_group_interval), settings, "balance-interval");
    filter_opt->fwmark = state->fwmark;

    parsePortSection(state, filter_opt, settings);
    configureMultiportBackend(filter_opt, state, settings);
    if (! copyIpMaskList(&filter_opt->white_list, &state->white_list) ||
        ! copyIpMaskList(&filter_opt->black_list, &state->black_list))
    {
        LOGF("UdpListener: failed to copy listener ACL into SocketManager filter options");
        return false;
    }

    filter_opt->host     = state->listen_address;
    filter_opt->port_min = state->listen_port_min;
    filter_opt->port_max = state->listen_port_max;
    filter_opt->protocol = IPPROTO_UDP;
    return true;
}

tunnel_t *udplistenerTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t), kAdapterChainHead);
    if (! t)
    {
        return NULL;
    }

    setupTunnelCallbacks(t);

    const cJSON          *settings = node->node_settings_json;
    udplistener_tstate_t *state    = tunnelGetState(t);

    state->white_list = vec_ipmask_t_init();
    state->black_list = vec_ipmask_t_init();

    if (! validateAndSetAddress(state, settings))
    {
        udplistenerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    getStringFromJsonObject(&(state->interface_name), settings, "interface");
    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", -1);
    parseIpMaskList(settings, "whitelist", &state->white_list);
    parseIpMaskList(settings, "blacklist", &state->black_list);

    state->workers_count     = (wid_t) getWorkersCount();
    state->worker_registries = memoryAllocateZero(sizeof(udplistener_worker_registry_t) * state->workers_count);
    if (state->worker_registries == NULL)
    {
        udplistenerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    for (wid_t wid = 0; wid < state->workers_count; ++wid)
    {
        state->worker_registries[wid].endpoints       = udplistener_endpoint_map_t_init();
        state->worker_registries[wid].next_generation = 1;
    }

    atomic_init(&state->dynamic_admission_open, true);

    socket_filter_option_t filter_opt;
    if (! setupFilterOptions(&filter_opt, state, settings))
    {
        socketfilteroptionDeInit(&filter_opt);
        udplistenerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    socketacceptorRegister(t, filter_opt, onUdpListenerFilteredPayloadReceived);

    return t;
}
