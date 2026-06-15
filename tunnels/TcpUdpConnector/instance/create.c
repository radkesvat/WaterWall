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

static char *tcpudpconnectorMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "TcpUdpConnector";
    return stringConcat(base, suffix);
}

static void tcpudpconnectorConfigureChildNode(node_t *child, node_t template_node, const node_t *owner,
                                              const char *suffix)
{
    *child = template_node;

    child->name      = tcpudpconnectorMakeChildName(owner, suffix);
    child->hash_name = calcHashBytes(child->name, stringLength(child->name));
    child->next      = NULL;
    child->hash_next = 0;
    child->version   = owner->version;

    child->node_json           = owner->node_json;
    child->node_settings_json  = owner->node_settings_json;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;

    child->can_have_next = false;
}

static bool tcpudpconnectorCreateChildTunnels(tunnel_t *t, node_t *node)
{
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);

    tcpudpconnectorConfigureChildNode(&ts->tcp_node, nodeTcpConnectorGet(), node, ".tcp-connector");
    tcpudpconnectorConfigureChildNode(&ts->udp_node, nodeUdpConnectorGet(), node, ".udp-connector");

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
