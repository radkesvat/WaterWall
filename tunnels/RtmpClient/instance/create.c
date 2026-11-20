#include "RtmpClient/structure.h"

tunnel_t *rtmpclientTunnelCreate(node_t *node)
{
    rtmp_settings_t settings = {0};
    if (! rtmpValidateSettingsObject(node) || ! rtmpReadClientUrl(node, &settings) ||
        ! rtmpReadCommonSettings(node, &settings))
    {
        return NULL;
    }
    tunnel_t *t = rtmpTunnelCreate(node, &settings, kRtmpClientRole, &rtmpclientOutput);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = rtmpclientTunnelUpStreamInit;
    t->fnPayloadU = rtmpclientTunnelUpStreamPayload;
    t->fnFinU     = rtmpclientTunnelUpStreamFinish;
    t->fnPauseU   = rtmpclientTunnelUpStreamPause;
    t->fnResumeU  = rtmpclientTunnelUpStreamResume;
    t->fnEstD     = rtmpclientTunnelDownStreamEst;
    t->fnPayloadD = rtmpclientTunnelDownStreamPayload;
    t->fnFinD     = rtmpclientTunnelDownStreamFinish;
    t->fnPauseD   = rtmpclientTunnelDownStreamPause;
    t->fnResumeD  = rtmpclientTunnelDownStreamResume;
    return t;
}
