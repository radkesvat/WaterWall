#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *sniffrouterTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(sniffrouter_tstate_t), sizeof(sniffrouter_lstate_t));

    t->fnInitU    = &sniffrouterTunnelUpStreamInit;
    t->fnEstU     = &sniffrouterTunnelUpStreamEst;
    t->fnFinU     = &sniffrouterTunnelUpStreamFinish;
    t->fnPayloadU = &sniffrouterTunnelUpStreamPayload;
    t->fnPauseU   = &sniffrouterTunnelUpStreamPause;
    t->fnResumeU  = &sniffrouterTunnelUpStreamResume;

    t->fnInitD    = &sniffrouterTunnelDownStreamInit;
    t->fnEstD     = &sniffrouterTunnelDownStreamEst;
    t->fnFinD     = &sniffrouterTunnelDownStreamFinish;
    t->fnPayloadD = &sniffrouterTunnelDownStreamPayload;
    t->fnPauseD   = &sniffrouterTunnelDownStreamPause;
    t->fnResumeD  = &sniffrouterTunnelDownStreamResume;

    t->onChain   = &sniffrouterTunnelOnChain;
    t->onIndex   = &sniffrouterTunnelOnIndex;
    t->onPrepare = &sniffrouterTunnelOnPrepair;
    t->onStart   = &sniffrouterTunnelOnStart;
    t->onDestroy = &sniffrouterTunnelDestroy;

    sniffrouter_tstate_t *ts = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: SniffRouter->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    char *web_name = NULL;
    if (! getStringFromJsonObject(&web_name, settings, "web"))
    {
        LOGF("SniffRouter: \"web\" (name of the http/web TcpConnector node) is required");
        tunnelDestroy(t);
        return NULL;
    }

    node_t *web_node = nodemanagerGetConfigNodeByName(node->node_manager_config, web_name);
    if (web_node == NULL)
    {
        LOGF("SniffRouter: web node \"%s\" not found", web_name);
        memoryFree(web_name);
        tunnelDestroy(t);
        return NULL;
    }
    memoryFree(web_name);

    if (web_node == node)
    {
        LOGF("SniffRouter: web node must not reference the SniffRouter itself");
        tunnelDestroy(t);
        return NULL;
    }

    if (! nodeHasNext(node))
    {
        LOGF("SniffRouter: must have a \"next\" (the tunnel branch, e.g. the user-side Bridge)");
        tunnelDestroy(t);
        return NULL;
    }

    ts->web_node = web_node;

    return t;
}
