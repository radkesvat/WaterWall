#include "structure.h"

tunnel_t *streamfragmenterTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(streamfragmenter_tstate_t), sizeof(streamfragmenter_lstate_t));
    if (t == NULL)
        return NULL;
    if (! streamfragmenterLoadSettings(tunnelGetState(t), node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }
    t->fnInitU    = streamfragmenterTunnelUpStreamInit;
    t->fnPayloadU = streamfragmenterTunnelUpStreamPayload;
    t->fnFinU     = streamfragmenterTunnelUpStreamFinish;
    t->fnFinD     = streamfragmenterTunnelDownStreamFinish;
    t->fnPauseD   = streamfragmenterTunnelDownStreamPause;
    t->fnResumeD  = streamfragmenterTunnelDownStreamResume;
    return t;
}
