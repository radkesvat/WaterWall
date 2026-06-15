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

static char *tcpudplistenerMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "TcpUdpListener";
    return stringConcat(base, suffix);
}

static void tcpudplistenerConfigureChildNode(node_t *child, node_t template_node, const node_t *owner,
                                             const char *suffix)
{
    *child = template_node;

    child->name      = tcpudplistenerMakeChildName(owner, suffix);
    child->hash_name = calcHashBytes(child->name, stringLength(child->name));
    child->next      = owner->name != NULL ? stringDuplicate(owner->name) : NULL;
    child->hash_next = owner->hash_name;
    child->version   = owner->version;

    child->node_json           = owner->node_json;
    child->node_settings_json  = owner->node_settings_json;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;

    child->can_have_prev = false;
}

static bool tcpudplistenerCreateChildTunnels(tunnel_t *t, node_t *node)
{
    tcpudplistener_tstate_t *ts = tunnelGetState(t);

    tcpudplistenerConfigureChildNode(&ts->tcp_node, nodeTcpListenerGet(), node, ".tcp-listener");
    tcpudplistenerConfigureChildNode(&ts->udp_node, nodeUdpListenerGet(), node, ".udp-listener");

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
