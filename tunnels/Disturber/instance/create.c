#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *disturberTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(disturber_tstate_t), sizeof(disturber_lstate_t));

    t->fnInitU    = &disturberTunnelUpStreamInit;
    t->fnEstU     = &disturberTunnelUpStreamEst;
    t->fnFinU     = &disturberTunnelUpStreamFinish;
    t->fnPayloadU = &disturberTunnelUpStreamPayload;
    t->fnPauseU   = &disturberTunnelUpStreamPause;
    t->fnResumeU  = &disturberTunnelUpStreamResume;

    t->fnInitD    = &disturberTunnelDownStreamInit;
    t->fnEstD     = &disturberTunnelDownStreamEst;
    t->fnFinD     = &disturberTunnelDownStreamFinish;
    t->fnPayloadD = &disturberTunnelDownStreamPayload;
    t->fnPauseD   = &disturberTunnelDownStreamPause;
    t->fnResumeD  = &disturberTunnelDownStreamResume;

    t->onPrepare = &disturberTunnelOnPrepair;
    t->onStart   = &disturberTunnelOnStart;
    t->onStop    = &disturberTunnelOnStop;
    t->onDestroy = &disturberTunnelDestroy;

    const cJSON        *settings = node->node_settings_json;
    disturber_tstate_t *ts       = tunnelGetState(t);

    getBoolFromJsonObjectOrDefault(&ts->disturb_upstream, settings, "disturb-upstream", true);
    getBoolFromJsonObjectOrDefault(&ts->disturb_downstream, settings, "disturb-downstream", false);
    getIntFromJsonObjectOrDefault(&ts->chance_instant_close, settings, "chance_instant_close", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_middle_close, settings, "chance_middle_close", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_payload_corruption, settings, "chance_payload_corruption", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_payload_loss, settings, "chance_payload_loss", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_payload_duplication, settings, "chance_payload_duplication", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_payload_out_of_order, settings, "chance_payload_out_of_order", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_payload_delay, settings, "chance_payload_delay", 0);
    getIntFromJsonObjectOrDefault(&ts->chance_connection_deadhang, settings, "chance_connection_deadhang", 0);
    getIntFromJsonObjectOrDefault(&ts->delay_min_ms, settings, "delay_min_ms", 0);
    getIntFromJsonObjectOrDefault(&ts->delay_max_ms, settings, "delay_max_ms", 0);

    if (ts->delay_min_ms < 0)
    {
        LOGW("Disturber: delay_min_ms was negative (%d), clamping to 0", ts->delay_min_ms);
        ts->delay_min_ms = 0;
    }
    if (ts->delay_max_ms < ts->delay_min_ms)
    {
        LOGW("Disturber: delay_max_ms (%d) < delay_min_ms (%d), clamping max to min",
             ts->delay_max_ms,
             ts->delay_min_ms);
        ts->delay_max_ms = ts->delay_min_ms;
    }

    return t;
}
