#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *muxserverTunnelCreate(node_t *node)
{
    int wc = getWorkersCount() - WORKER_ADDITIONS;

    tunnel_t *t = tunnelCreate(node, sizeof(muxserver_tstate_t) + (wc * sizeof(line_t *)), sizeof(muxserver_lstate_t));

    t->fnInitU    = &muxserverTunnelUpStreamInit;
    t->fnEstU     = &muxserverTunnelUpStreamEst;
    t->fnFinU     = &muxserverTunnelUpStreamFinish;
    t->fnPayloadU = &muxserverTunnelUpStreamPayload;
    t->fnPauseU   = &muxserverTunnelUpStreamPause;
    t->fnResumeU  = &muxserverTunnelUpStreamResume;

    t->fnInitD    = &muxserverTunnelDownStreamInit;
    t->fnEstD     = &muxserverTunnelDownStreamEst;
    t->fnFinD     = &muxserverTunnelDownStreamFinish;
    t->fnPayloadD = &muxserverTunnelDownStreamPayload;
    t->fnPauseD   = &muxserverTunnelDownStreamPause;
    t->fnResumeD  = &muxserverTunnelDownStreamResume;

    t->onPrepair = &muxserverTunnelOnPrepair;
    t->onStart   = &muxserverTunnelOnStart;
    t->onDestroy = &muxserverTunnelDestroy;

    // const cJSON        *settings = node->node_settings_json;
    // muxserver_tstate_t *ts       = tunnelGetState(t);


    return t;
}
