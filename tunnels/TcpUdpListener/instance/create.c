#include "structure.h"

#include "loggers/network_logger.h"

static void tcpudplistenerConfigureCallbacks(tunnel_t *t)
{
    t->fnInitU    = &tcpudplistenerTunnelUpStreamInit;
    t->fnEstU     = &tcpudplistenerTunnelUpStreamEst;
    t->fnFinU     = &tcpudplistenerTunnelUpStreamFinish;
    t->fnPayloadU = &tcpudplistenerTunnelUpStreamPayload;
    t->fnPauseU   = &tcpudplistenerTunnelUpStreamPause;
    t->fnResumeU  = &tcpudplistenerTunnelUpStreamResume;

    t->fnInitD    = &tcpudplistenerTunnelDownStreamInit;
    t->fnEstD     = &tcpudplistenerTunnelDownStreamEst;
    t->fnFinD     = &tcpudplistenerTunnelDownStreamFinish;
    t->fnPayloadD = &tcpudplistenerTunnelDownStreamPayload;
    t->fnPauseD   = &tcpudplistenerTunnelDownStreamPause;
    t->fnResumeD  = &tcpudplistenerTunnelDownStreamResume;

    t->onChain      = &tcpudplistenerTunnelOnChain;
    t->onIndex      = &tcpudplistenerTunnelOnIndex;
    t->onPrepare    = &tcpudplistenerTunnelOnPrepair;
    t->onStart      = &tcpudplistenerTunnelOnStart;
    t->onStop       = &tcpudplistenerTunnelOnStop;
    t->onWorkerStop = &tcpudplistenerTunnelOnWorkerStop;
    t->onDestroy    = &tcpudplistenerTunnelDestroy;
}

static bool tcpudplistenerConfigureChildNode(node_t *child, node_t template_node, const node_t *owner,
                                             const char *suffix)
{
    if (! nodeConfigureChild(child, template_node, owner, suffix, kNodeChildLinkOwnerSelf, owner->node_settings_json))
    {
        return false;
    }

    child->can_have_prev = false;
    return true;
}

static bool tcpudplistenerCreateChildTunnels(tunnel_t *t, node_t *node)
{
    tcpudplistener_tstate_t *ts = tunnelGetState(t);

    if (! tcpudplistenerConfigureChildNode(&ts->tcp_node, nodeTcpListenerGet(), node, ".tcp-listener"))
    {
        LOGF("TcpUdpListener: failed to configure internal TcpListener node");
        return false;
    }
    if (! tcpudplistenerConfigureChildNode(&ts->udp_node, nodeUdpListenerGet(), node, ".udp-listener"))
    {
        LOGF("TcpUdpListener: failed to configure internal UdpListener node");
        return false;
    }

    ts->tcp_listener = ts->tcp_node.createHandle(&ts->tcp_node);
    if (ts->tcp_listener == NULL)
    {
        LOGF("TcpUdpListener: failed to create internal TcpListener");
        return false;
    }
    ts->tcp_node.instance = ts->tcp_listener;

    ts->udp_listener = ts->udp_node.createHandle(&ts->udp_node);
    if (ts->udp_listener == NULL)
    {
        LOGF("TcpUdpListener: failed to create internal UdpListener");
        return false;
    }
    ts->udp_node.instance = ts->udp_listener;

    return true;
}

tunnel_t *tcpudplistenerTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpudplistener_tstate_t), 0);
    tcpudplistenerConfigureCallbacks(t);

    if (! nodeHasNext(node))
    {
        LOGF("TcpUdpListener: a next node is required");
        tcpudplistenerTunnelDestroy(t);
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(node->node_settings_json))
    {
        LOGF("JSON Error: TcpUdpListener->settings (object field) : The object was empty or invalid");
        tcpudplistenerTunnelDestroy(t);
        return NULL;
    }

    if (! tcpudplistenerCreateChildTunnels(t, node))
    {
        tcpudplistenerTunnelDestroy(t);
        return NULL;
    }

    return t;
}
