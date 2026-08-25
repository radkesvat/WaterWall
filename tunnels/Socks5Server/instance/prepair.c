#include "structure.h"

#include "loggers/network_logger.h"

static hash_t socks5serverUdpListenerTypeHash(void)
{
    const char *type_name = "UdpListener";
    return calcHashBytes(type_name, stringLength(type_name));
}

static hash_t socks5serverTcpUdpListenerTypeHash(void)
{
    const char *type_name = "TcpUdpListener";
    return calcHashBytes(type_name, stringLength(type_name));
}

bool socks5serverResolveDynamicProvider(tunnel_t *t)
{
    socks5server_tstate_t *ts = tunnelGetState(t);
    ts->dynamic_provider      = (udplistener_dynamic_provider_t) {0};

    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! tunnelchainIsFinalized(chain))
    {
        return false;
    }

    tunnel_t *listener = NULL;
    tunnel_t *p        = t->prev;
    for (uint16_t hops = 0; p != NULL && hops < kMaxChainLen; ++hops, p = p->prev)
    {
        if (p->node == NULL)
        {
            continue;
        }

        if (p->node->hash_type == socks5serverUdpListenerTypeHash())
        {
            ts->dynamic_provider = udplistenerGetDynamicProvider(p);
            listener             = p;
            break;
        }
        if (p->node->hash_type == socks5serverTcpUdpListenerTypeHash())
        {
            ts->dynamic_provider = tcpudplistenerGetDynamicProvider(p);
            listener             = p;
            break;
        }
    }

    if (listener == NULL || ts->dynamic_provider.instance == NULL || ts->dynamic_provider.open == NULL ||
        ts->dynamic_provider.activate == NULL || ts->dynamic_provider.close == NULL ||
        ts->dynamic_provider.get_line_info == NULL)
    {
        return false;
    }

    if (tunnelGetChain(listener) != chain || tunnelGetChain(ts->dynamic_provider.instance) != chain)
    {
        ts->dynamic_provider = (udplistener_dynamic_provider_t) {0};
        return false;
    }

    bool      reaches = false;
    tunnel_t *f       = ts->dynamic_provider.instance;
    for (uint16_t hops = 0; f != NULL && hops < kMaxChainLen; ++hops, f = f->next)
    {
        if (f == t)
        {
            reaches = true;
            break;
        }
    }

    if (! reaches)
    {
        ts->dynamic_provider = (udplistener_dynamic_provider_t) {0};
        return false;
    }

    return true;
}

void socks5serverTunnelOnPrepair(tunnel_t *t)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    if (ts->allow_udp)
    {
        if (! socks5serverResolveDynamicProvider(t))
        {
            LOGF("Socks5Server: could not resolve dynamic UDP provider from preceding UdpListener / TcpUdpListener in "
                 "chain");
            startupFailureRecord(1);
            return;
        }
    }

    if (ts->no_auth)
    {
        return;
    }

    if (ts->auth_client_node == NULL)
    {
        LOGF("Socks5Server: auth-client-node-name was not resolved during create");
        startupFailureRecord(1);
        return;
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("Socks5Server: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        startupFailureRecord(1);
        return;
    }
}
