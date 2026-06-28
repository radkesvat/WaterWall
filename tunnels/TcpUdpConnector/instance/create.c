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

    t->fnInitD    = &tcpudpconnectorTunnelDownStreamInit;
    t->fnEstD     = &tcpudpconnectorTunnelDownStreamEst;
    t->fnFinD     = &tcpudpconnectorTunnelDownStreamFinish;
    t->fnPayloadD = &tcpudpconnectorTunnelDownStreamPayload;
    t->fnPauseD   = &tcpudpconnectorTunnelDownStreamPause;
    t->fnResumeD  = &tcpudpconnectorTunnelDownStreamResume;

    t->onChain      = &tcpudpconnectorTunnelOnChain;
    t->onIndex      = &tcpudpconnectorTunnelOnIndex;
    t->onPrepare    = &tcpudpconnectorTunnelOnPrepair;
    t->onStart      = &tcpudpconnectorTunnelOnStart;
    t->onStop       = &tcpudpconnectorTunnelOnStop;
    t->onWorkerStop = &tcpudpconnectorTunnelOnWorkerStop;
    t->onDestroy    = &tcpudpconnectorTunnelDestroy;
}

static bool tcpudpconnectorConfigureChildNode(node_t *child, node_t template_node, const node_t *owner,
                                              const char *suffix)
{
    if (! nodeConfigureChild(child, template_node, owner, suffix, kNodeChildLinkNone, owner->node_settings_json))
    {
        return false;
    }

    child->can_have_next = false;
    return true;
}

static bool tcpudpconnectorCreateChildTunnels(tunnel_t *t, node_t *node)
{
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);

    if (! tcpudpconnectorConfigureChildNode(&ts->tcp_node, nodeTcpConnectorGet(), node, ".tcp-connector"))
    {
        LOGF("TcpUdpConnector: failed to configure internal TcpConnector node");
        return false;
    }
    if (! tcpudpconnectorConfigureChildNode(&ts->udp_node, nodeUdpConnectorGet(), node, ".udp-connector"))
    {
        LOGF("TcpUdpConnector: failed to configure internal UdpConnector node");
        return false;
    }

    ts->tcp_connector = ts->tcp_node.createHandle(&ts->tcp_node);
    if (ts->tcp_connector == NULL)
    {
        LOGF("TcpUdpConnector: failed to create internal TcpConnector");
        return false;
    }
    ts->tcp_node.instance = ts->tcp_connector;

    ts->udp_connector = ts->udp_node.createHandle(&ts->udp_node);
    if (ts->udp_connector == NULL)
    {
        LOGF("TcpUdpConnector: failed to create internal UdpConnector");
        return false;
    }
    ts->udp_node.instance = ts->udp_connector;

    return true;
}

tunnel_t *tcpudpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpudpconnector_tstate_t), sizeof(tcpudpconnector_lstate_t));
    tcpudpconnectorConfigureCallbacks(t);

    if (nodeHasNext(node))
    {
        LOGF("TcpUdpConnector: this node is a chain end and must not have a next node");
        tcpudpconnectorTunnelDestroy(t);
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(node->node_settings_json))
    {
        LOGF("JSON Error: TcpUdpConnector->settings (object field) : The object was empty or invalid");
        tcpudpconnectorTunnelDestroy(t);
        return NULL;
    }

    if (! tcpudpconnectorCreateChildTunnels(t, node))
    {
        tcpudpconnectorTunnelDestroy(t);
        return NULL;
    }

    return t;
}
