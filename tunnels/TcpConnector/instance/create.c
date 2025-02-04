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
    if (state->dest_addr_selected.status == kDvsConstant)
    {
        char *slash = strchr(state->dest_addr_selected.value_ptr, '/');
        if (slash != NULL)
        {
            *slash                                 = '\0';
            int prefix_length                      = atoi(slash + 1);
            state->constant_dest_addr.address_type = getHostAddrType(state->dest_addr_selected.value_ptr);

            if (prefix_length < 0)
            {
                LOGF("TcpConnector: outbound ip/subnet range is invalid");
                exit(1);
            }

            if (state->constant_dest_addr.address_type == kSatIPV4)
            {
                if (prefix_length > 32)
                {
                    LOGF("TcpConnector: outbound ip/subnet range is invalid");
                    exit(1);
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
            else
            {
                if (64 > prefix_length) // limit to 64
                {
                    LOGF("TcpConnector: outbound ip/subnet range is invalid");
                    exit(1);
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
        else
        {
            state->constant_dest_addr.address_type = getHostAddrType(state->dest_addr_selected.value_ptr);
        }

        if (state->constant_dest_addr.address_type == kSatDomainName)
        {
            connectionContextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.value_ptr,
                                               strlen(state->dest_addr_selected.value_ptr));
        }
        else
        {

            sockaddrSetIp(&(state->constant_dest_addr.address), state->dest_addr_selected.value_ptr);
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
        connectionContextPortSet(&(state->constant_dest_addr), state->dest_port_selected.value);
    }

    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", kFwMarkInvalid);

    return t;
}
