#include "structure.h"

#include "loggers/network_logger.h"

static void parsePortSection(udplistener_tstate_t *state, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if ((cJSON_IsNumber(port_json) && (port_json->valuedouble != 0)))
    {
        // single port given as a number
        state->listen_port_min = (uint16_t) port_json->valuedouble;
        state->listen_port_max = (uint16_t) port_json->valuedouble;
    }
    else
    {
        if (cJSON_IsArray(port_json) && cJSON_GetArraySize(port_json) == 2)
        {
            // multi port given
            const cJSON *port_minmax;
            int          i = 0;
            cJSON_ArrayForEach(port_minmax, port_json)
            {
                if (! (cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
                {
                    LOGF("JSON Error: UdpListener->settings->port (number-or-array field) : The data was empty or "
                         "invalid");
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
        else
        {
            LOGF("JSON Error: UdpListener->settings->port (number-or-array field) : The data was empty or invalid");
            terminateProgram(1);
        }
    }
}

tunnel_t *udplistenerTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udplistener_tstate_t), sizeof(udplistener_lstate_t));

    t->fnInitU    = &udplistenerTunnelUpStreamInit;
    t->fnEstU     = &udplistenerTunnelUpStreamEst;
    t->fnFinU     = &udplistenerTunnelUpStreamFinish;
    t->fnPayloadU = &udplistenerTunnelUpStreamPayload;
    t->fnPauseU   = &udplistenerTunnelUpStreamPause;
    t->fnResumeU  = &udplistenerTunnelUpStreamResume;

    t->fnInitD    = &udplistenerTunnelDownStreamInit;
    t->fnEstD     = &udplistenerTunnelDownStreamEst;
    t->fnFinD     = &udplistenerTunnelDownStreamFinish;
    t->fnPayloadD = &udplistenerTunnelDownStreamPayload;
    t->fnPauseD   = &udplistenerTunnelDownStreamPause;
    t->fnResumeD  = &udplistenerTunnelDownStreamResume;

    t->onPrepair = &udplistenerTunnelOnPrepair;
    t->onStart   = &udplistenerTunnelOnStart;
    t->onDestroy = &udplistenerTunnelDestroy;

    const cJSON *settings = node->node_settings_json;
    
    udplistener_tstate_t *state = tunnelGetState(t);

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: UdpListener->settings (object field) : The object was empty or invalid");
        return NULL;
    }


    if (! getStringFromJsonObject(&(state->listen_address), settings, "address"))
    {
        LOGF("JSON Error: UdpListener->settings->address (string field) : The data was empty or invalid");
        return NULL;
    }

    socket_filter_option_t filter_opt;
    socketfilteroptionInit(&filter_opt);


    getStringFromJsonObject(&(filter_opt.interface), settings, "interface");

    getStringFromJsonObject(&(filter_opt.balance_group_name), settings, "balance-group");
    getIntFromJsonObject((int *) &(filter_opt.balance_group_interval), settings, "balance-interval");

    filter_opt.multiport_backend = kMultiportBackendNone;
    parsePortSection(state, settings);

    if (state->listen_port_max != 0)
    {
        filter_opt.multiport_backend = kMultiportBackendDefault;
        dynamic_value_t dy_mb =
            parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
        if (dy_mb.status == 2)
        {
            filter_opt.multiport_backend = kMultiportBackendIptables;
        }
        if (dy_mb.status == 3)
        {
            filter_opt.multiport_backend = kMultiportBackendSockets;
        }
    }

    const cJSON *wlist          = cJSON_GetObjectItemCaseSensitive(settings, "whitelist");
    if (cJSON_IsArray(wlist))
    {
        int len = cJSON_GetArraySize(wlist);
        if (len > 0)
        {

            int          i         = 0;
            const cJSON *list_item = NULL;
            cJSON_ArrayForEach(list_item, wlist)
            {
                char    *ip_str = NULL;
                ipmask_t ipmask;

                if (! getStringFromJson(&(ip_str), list_item) || ! verifyIPCdir(ip_str))
                {
                    LOGF("JSON Error: UdpListener->settings->whitelist (array of strings field) index %d : The data "
                         "was empty or invalid",
                         i);
                    terminateProgram(1);
                }

                int parse_result = parseIPWithSubnetMask(ip_str, &(ipmask.ip), &(ipmask.mask));

                if (parse_result == -1)
                {
                    LOGF("UdpListener: stopping due to whitelist address [%d] \"%s\" parse failure", i, ip_str);
                    terminateProgram(1);
                }
                vec_ipmask_t_push(&filter_opt.white_list, ipmask);

                i++;
            }
        }
    }

    filter_opt.host             = state->listen_address;
    filter_opt.port_min         = state->listen_port_min;
    filter_opt.port_max         = state->listen_port_max;
    filter_opt.protocol         = kSocketProtocolTcp;
   
    socketacceptorRegister(t, filter_opt, onUdpListenerFilteredPayloadReceived);

    
    return t;
}
