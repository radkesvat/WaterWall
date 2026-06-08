#include "structure.h"

#include "loggers/network_logger.h"

static bool connectionfisherclientLoadTries(connectionfisherclient_tstate_t *ts, const cJSON *settings)
{
    int simultaneous_tries = 2;

    if (settings != NULL)
    {
        getIntFromJsonObjectOrDefault(&simultaneous_tries, settings, "simultaneous-tries-perline", 2);
    }

    if (simultaneous_tries < 1)
    {
        LOGF("JSON Error: ConnectionFisherClient->settings->simultaneous-tries-perline (int field) : expected a value "
             ">= 1");
        return false;
    }

    ts->simultaneous_tries_perline = (uint32_t) simultaneous_tries;
    return true;
}

tunnel_t *connectionfisherclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(connectionfisherclient_tstate_t), sizeof(connectionfisherclient_lstate_t));
    connectionfisherclient_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &connectionfisherclientTunnelUpStreamInit;
    t->fnEstU     = &connectionfisherclientTunnelUpStreamEst;
    t->fnFinU     = &connectionfisherclientTunnelUpStreamFinish;
    t->fnPayloadU = &connectionfisherclientTunnelUpStreamPayload;
    t->fnPauseU   = &connectionfisherclientTunnelUpStreamPause;
    t->fnResumeU  = &connectionfisherclientTunnelUpStreamResume;

    t->fnInitD    = &connectionfisherclientTunnelDownStreamInit;
    t->fnEstD     = &connectionfisherclientTunnelDownStreamEst;
    t->fnFinD     = &connectionfisherclientTunnelDownStreamFinish;
    t->fnPayloadD = &connectionfisherclientTunnelDownStreamPayload;
    t->fnPauseD   = &connectionfisherclientTunnelDownStreamPause;
    t->fnResumeD  = &connectionfisherclientTunnelDownStreamResume;

    t->onStop    = &connectionfisherclientTunnelOnStop;
    t->onDestroy = &connectionfisherclientTunnelDestroy;

    ts->simultaneous_tries_perline = 2;

    if (! connectionfisherclientLoadTries(ts, node->node_settings_json))
    {
        connectionfisherclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}
