#include "RtmpServer/structure.h"

tunnel_t *rtmpserverTunnelCreate(node_t *node)
{
    rtmp_settings_t settings = {0};
    if (! rtmpValidateSettingsObject(node) || ! rtmpReadCommonSettings(node, &settings))
    {
        return NULL;
    }
    tunnel_t *t = rtmpTunnelCreate(node, &settings, kRtmpServerRole, &rtmpserverOutput);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = rtmpserverTunnelUpStreamInit;
    t->fnPayloadU = rtmpserverTunnelUpStreamPayload;
    t->fnFinU     = rtmpserverTunnelUpStreamFinish;
    t->fnPauseU   = rtmpserverTunnelUpStreamPause;
    t->fnResumeU  = rtmpserverTunnelUpStreamResume;
    t->fnEstD     = rtmpserverTunnelDownStreamEst;
    t->fnPayloadD = rtmpserverTunnelDownStreamPayload;
    t->fnFinD     = rtmpserverTunnelDownStreamFinish;
    t->fnPauseD   = rtmpserverTunnelDownStreamPause;
    t->fnResumeD  = rtmpserverTunnelDownStreamResume;
    return t;
}
