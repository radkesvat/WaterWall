#include "structure.h"

#include "loggers/network_logger.h"

static void tcpudpconnectorConfigureCallbacks(tunnel_t *t)
{
    t->fnInitU    = &tcpudpconnectorTunnelUpStreamInit;
    t->fnEstU     = &tcpudpconnectorTunnelUpStreamEst;
    t->fnFinU     = &tcpudpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &tcpudpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &tcpudpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &tcpudpconnectorTunnelUpStreamResume;

    t->fnFinD = &tcpudpconnectorTunnelDownStreamFinish;

    t->onChain      = &tcpudpconnectorTunnelOnChain;
    t->onDestroy    = &tcpudpconnectorTunnelDestroy;
}

static bool tcpudpconnectorConfigureChildNode(node_t *child, node_t template_node, const node_t *owner,
                                              const char *suffix, cJSON *settings)
{
    if (! nodeConfigureChild(child, template_node, owner, suffix, kNodeChildLinkNone, settings))
    {
        return false;
    }

    child->can_have_next = false;
    return true;
}

static bool tcpudpconnectorCreateChildTunnels(tunnel_t *t, node_t *node)
{
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);

    if (! tcpudpconnectorConfigureChildNode(
            &ts->tcp_node, nodeTcpConnectorGet(), node, ".tcp-connector", ts->child_settings))
    {
        LOGF("TcpUdpConnector: failed to configure internal TcpConnector node");
        return false;
    }
    if (! tcpudpconnectorConfigureChildNode(
            &ts->udp_node, nodeUdpConnectorGet(), node, ".udp-connector", ts->child_settings))
    {
        LOGF("TcpUdpConnector: failed to configure internal UdpConnector node");
        return false;
    }

    ts->tcp_connector = nodemanagerCreateTunnelInstance(&ts->tcp_node);
    if (ts->tcp_connector == NULL)
    {
        LOGF("TcpUdpConnector: failed to create internal TcpConnector");
        return false;
    }
    ts->tcp_node.instance = ts->tcp_connector;

    ts->udp_connector = nodemanagerCreateTunnelInstance(&ts->udp_node);
    if (ts->udp_connector == NULL)
    {
        LOGF("TcpUdpConnector: failed to create internal UdpConnector");
        return false;
    }
    ts->udp_node.instance = ts->udp_connector;
    tcpconnectorTunnelSetDnsProvider(ts->tcp_connector, ts->resolver);
    udpconnectorTunnelSetDnsProvider(ts->udp_connector, ts->resolver);

    return true;
}

static bool tcpudpconnectorCreateDnsProvider(tunnel_t *t, node_t *node)
{
    tcpudpconnector_tstate_t   *ts       = tunnelGetState(t);
    const dns_policy_defaults_t defaults = {
        .resolve          = true,
        .strategy         = GSTATE.domain_strategy,
        .core_strategy    = GSTATE.domain_strategy,
        .require_dns_next = true,
    };
    if (! dnsPolicyParseSettings(&ts->dns_policy, node->node_settings_json, &defaults, "TcpUdpConnector->settings"))
        return false;
    ts->resolver_settings = dnsPolicyCreateResolverSettings(&ts->dns_policy);
    if (! nodeConfigureChild(&ts->resolver_node,
                             nodeDomainResolverGet(),
                             node,
                             ".dns-provider",
                             kNodeChildLinkNone,
                             ts->resolver_settings))
        return false;
    ts->resolver_node.flags |= kNodeFlagNoChain;
    ts->resolver_node.can_have_prev         = false;
    ts->resolver_node.can_have_next         = false;
    ts->resolver_node.layer_group           = kNodeLayer4;
    ts->resolver_node.layer_group_prev_node = kNodeLayerNone;
    ts->resolver_node.layer_group_next_node = kNodeLayerNone;
    ts->resolver                            = nodemanagerCreateTunnelInstance(&ts->resolver_node);
    if (ts->resolver == NULL)
        return false;
    ts->resolver_node.instance = ts->resolver;

    /* Private children retain their own preparation storage but borrow this
     * provider. Construct them with transport-free settings to avoid creating
     * duplicate explicit branches or direct-mode connector trees. */
    ts->child_settings = cJSON_Duplicate(node->node_settings_json, true);
    cJSON_DeleteItemFromObjectCaseSensitive(ts->child_settings, "dns-behaviour");
    cJSON *child_policy = cJSON_AddObjectToObject(ts->child_settings, "dns-behaviour");
    cJSON_AddBoolToObject(child_policy, "resolve", ts->dns_policy.resolve);
    if (ts->dns_policy.resolve)
        cJSON_AddItemToObject(
            child_policy,
            "strategy",
            cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(ts->resolver_settings, "strategy"), true));
    return true;
}

tunnel_t *tcpudpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpudpconnector_tstate_t), sizeof(tcpudpconnector_lstate_t));
    if (! t)
    {
        return NULL;
    }

    tcpudpconnectorConfigureCallbacks(t);

    if (nodeHasNext(node))
    {
        LOGF("TcpUdpConnector: this node is a chain end and must not have a next node");
        tcpudpconnectorTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(node->node_settings_json))
    {
        LOGF("JSON Error: TcpUdpConnector->settings (object field) : The object was empty or invalid");
        tcpudpconnectorTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! tcpudpconnectorCreateDnsProvider(t, node) || ! tcpudpconnectorCreateChildTunnels(t, node))
    {
        tcpudpconnectorTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
