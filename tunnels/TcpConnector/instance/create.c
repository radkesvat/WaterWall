#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcpconnector_tstate_t), sizeof(tcpconnector_lstate_t), true);

    t->fnInitU    = &tcpconnectorTunnelUpStreamInit;
    t->fnEstU     = &tcpconnectorTunnelUpStreamEst;
    t->fnFinU     = &tcpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &tcpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &tcpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &tcpconnectorTunnelUpStreamResume;

    t->onPrepair = &tcpconnectorTunnelOnPrepair;
    t->onStart   = &tcpconnectorTunnelOnStart;
    t->onDestroy = &tcpconnectorTunnelDestroy;

    tcpconnector_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&(state->option_tcp_no_delay), settings, "nodelay", true);
    getBoolFromJsonObjectOrDefault(&(state->option_tcp_fast_open), settings, "fastopen", false);
    getBoolFromJsonObjectOrDefault(&(state->option_reuse_addr), settings, "reuseaddr", false);
    getIntFromJsonObjectOrDefault(&(state->domain_strategy), settings, "domain-strategy", 0);

    state->dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (state->dest_addr_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: TcpConnector->settings->address (string field) : The vaule was empty or invalid");
        return NULL;
    }

    /**
        TODO
        this is old code, i think the free bind part may not work if getIpVersion consider that slash
    */
    state->constant_dest_addr.ip_address.type = getIpVersion(state->dest_addr_selected.string);

    if (state->constant_dest_addr.ip_address.type == IPADDR_TYPE_ANY)
    {
        // its a domain
        state->constant_dest_addr.type_ip = false;
    }
    else
    {
        state->constant_dest_addr.type_ip = true;
    }

    // Free bind parsings
    if (state->dest_addr_selected.status == kDvsConstant)
    {
        char *slash = stringChr(state->dest_addr_selected.string, '/');
        if (slash != NULL)
        {
            *slash            = '\0';
            int prefix_length = atoi(slash + 1);

            if (prefix_length < 0)
            {
                LOGF("TcpConnector: outbound ip/subnet range is invalid");
                terminateProgram(1);
            }

            if (state->constant_dest_addr.ip_address.type == AF_INET)
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

                // uint32_t mask;
                // if (prefix_length > 0)
                // {
                //     mask = htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - prefix_length)));
                // }
                // else
                // {
                //     mask = 0;
                // }
                // uint32_t calc = ((uint32_t) state->constant_dest_addr.address.sin.sin_addr.s_addr) & mask;
                // memoryCopy(&(state->constant_dest_addr.address.sin.sin_addr), &calc, sizeof(struct in_addr));
            }
            else if (state->constant_dest_addr.ip_address.type == AF_INET6)
            {
                if (64 > prefix_length) // limit to 64
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

                // uint8_t *addr_ptr = (uint8_t *) &(state->constant_dest_addr.address.sin6.sin6_addr);

                // for (int i = 0; i < 16; i++)
                // {
                //     int bits    = prefix_length >= 8 ? 8 : prefix_length;
                //     addr_ptr[i] = bits == 0 ? 0 : addr_ptr[i] & (0xFF << (8 - bits));
                //     prefix_length -= bits;
                // }
            }
        }

        if (state->constant_dest_addr.type_ip == false)
        {
            addresscontextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.string,
                                            (uint8_t) stringLength(state->dest_addr_selected.string));
        }
        else
        {
            sockaddr_u temp;
            sockaddrSetIp(&(temp), state->dest_addr_selected.string);
            sockaddrToIpAddr(&temp,&(state->constant_dest_addr.ip_address));
        }
    }

    state->dest_port_selected =
        parseDynamicNumericValueFromJsonObject(settings, "port", 2, "src_context->port", "dest_context->port");

    if (state->dest_port_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: TcpConnector->settings->port (number field) : The vaule was empty or invalid");
        return NULL;
    }

    if (state->dest_port_selected.status == kDvsConstant)
    {
        addresscontextSetPort(&(state->constant_dest_addr), (uint16_t) state->dest_port_selected.integer);
    }

    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", kFwMarkInvalid);

    return t;
}
