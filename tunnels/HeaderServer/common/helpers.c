#include "structure.h"

#include "loggers/network_logger.h"

static bool headerserverParsePort(uint16_t *out, const cJSON *value, const char *json_path)
{
    if (! cJSON_IsNumber(value))
    {
        LOGF("HeaderServer: %s must be a port number or \"dest_context->port\"", json_path);
        return false;
    }

    if (value->valueint <= 0 || value->valueint > UINT16_MAX)
    {
        LOGF("HeaderServer: %s must be in range [1, %u]", json_path, (unsigned int) UINT16_MAX);
        return false;
    }

    *out = (uint16_t) value->valueint;
    return true;
}

bool headerserverLoadSettings(headerserver_tstate_t *ts, const cJSON *settings)
{
    dynamic_value_t override =
        parseDynamicNumericValueFromJsonObject(settings, "override", 2, "dest_context->port", "line->dest_ctx->port");

    switch (override.status)
    {
    case kDvsFirstOption:
    case kDvsSecondOption:
        ts->override_mode = kHeaderServerOverrideModeHeaderPort;
        return true;

    case kDvsConstant: {
        const cJSON *override_json = cJSON_GetObjectItemCaseSensitive(settings, "override");
        ts->override_mode          = kHeaderServerOverrideModeConstant;
        return headerserverParsePort(&ts->constant_port, override_json, "settings.override");
    }

    default:
        LOGF("HeaderServer: settings.override is required and must be a port number or \"dest_context->port\"");
        return false;
    }
}

void headerserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    lineLock(l);

    headerserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kHeaderServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    bool close_next = ls->phase == kHeaderServerPhaseEstablished;

    headerserverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}

void headerserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    lineLock(l);

    headerserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kHeaderServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    headerserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);

    lineUnlock(l);
}

void headerserverCloseLineFromProtocolError(tunnel_t *t, line_t *l)
{
    lineLock(l);

    headerserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kHeaderServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    bool close_next = ls->phase == kHeaderServerPhaseEstablished;

    headerserverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}
