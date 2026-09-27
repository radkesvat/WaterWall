#include "UserController/interface.h"
#include "internal.h"
#include "loggers/network_logger.h"

tunnel_t *httpproxyserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(hps_tstate_t), sizeof(hps_lstate_t));
    if (! t)
        return NULL;
    hps_tstate_t *ts   = tunnelGetState(t);
    t->fnInitU         = httpproxyserverTunnelUpStreamInit;
    t->fnFinU          = httpproxyserverTunnelUpStreamFinish;
    t->fnPayloadU      = httpproxyserverTunnelUpStreamPayload;
    t->fnPauseU        = httpproxyserverTunnelUpStreamPause;
    t->fnResumeU       = httpproxyserverTunnelUpStreamResume;
    t->fnEstD          = httpproxyserverTunnelDownStreamEst;
    t->fnFinD          = httpproxyserverTunnelDownStreamFinish;
    t->fnPayloadD      = httpproxyserverTunnelDownStreamPayload;
    t->fnPauseD        = httpproxyserverTunnelDownStreamPause;
    t->fnResumeD       = httpproxyserverTunnelDownStreamResume;
    t->onChain         = httpproxyserverTunnelOnChain;
    t->onPrepare       = httpproxyserverTunnelOnPrepair;
    t->onWorkerQuiesce = httpproxyserverTunnelOnWorkerQuiesce;
    t->onWorkerStop    = httpproxyserverTunnelOnWorkerStop;
    t->onDestroy       = httpproxyserverTunnelDestroy;
    if (! hpsParseSettings(ts, node))
    {
        LOGF("HttpProxyServer: invalid settings, authentication selection, or missing next node");
        goto fail;
    }
    ts->worker_count = getWorkersCount();
    ts->workers      = memoryAllocateZero(sizeof(*ts->workers) * ts->worker_count);
    if (! ts->workers)
        goto fail;
    if (ts->auth_mode == kHpsAuthTracked)
    {
        if (! nodeConfigureChild(&ts->controller_node,
                                 nodeUserControllerGet(),
                                 node,
                                 ".user-controller",
                                 kNodeChildLinkOwnerNext,
                                 node->node_settings_json))
            goto fail;
        ts->controller = nodemanagerCreateTunnelInstance(&ts->controller_node);
        if (! ts->controller)
            goto fail;
        ts->controller_node.instance = ts->controller;
    }
    return t;
fail:
    httpproxyserverTunnelDestroy(t, NULL);
    return NULL;
}
