#include "structure.h"

#include "loggers/network_logger.h"

static bool loggertunnelParseMode(loggertunnel_tstate_t *state, const cJSON *settings)
{
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "mode");

    if (! (cJSON_IsString(mode) && mode->valuestring != NULL))
    {
        LOGF("LoggerTunnel: settings.mode is required");
        return false;
    }

    if (stringCompare(mode->valuestring, "log") == 0)
    {
        state->mode = kLoggerTunnelModeLog;
        return true;
    }

    if (stringCompare(mode->valuestring, "file") == 0)
    {
        state->mode = kLoggerTunnelModeFile;
        return true;
    }

    if (stringCompare(mode->valuestring, "tcp-payload-file") == 0)
    {
        state->mode = kLoggerTunnelModeTcpPayloadFile;
        return true;
    }

    LOGF("LoggerTunnel: settings.mode must be one of log, file, or tcp-payload-file");
    return false;
}

static bool loggertunnelParseLevel(loggertunnel_tstate_t *state, const cJSON *settings)
{
    const cJSON *level = cJSON_GetObjectItemCaseSensitive(settings, "level");

    if (level == NULL)
    {
        state->log_level = LOG_LEVEL_DEBUG;
        return true;
    }

    if (! (cJSON_IsString(level) && level->valuestring != NULL))
    {
        LOGF("LoggerTunnel: settings.level must be a string when mode is log");
        return false;
    }

    if (stringCompare(level->valuestring, "debug") == 0)
    {
        state->log_level = LOG_LEVEL_DEBUG;
        return true;
    }

    if (stringCompare(level->valuestring, "info") == 0)
    {
        state->log_level = LOG_LEVEL_INFO;
        return true;
    }

    if (stringCompare(level->valuestring, "warning") == 0)
    {
        state->log_level = LOG_LEVEL_WARN;
        return true;
    }

    if (stringCompare(level->valuestring, "error") == 0)
    {
        state->log_level = LOG_LEVEL_ERROR;
        return true;
    }

    if (stringCompare(level->valuestring, "fatal") == 0)
    {
        state->log_level = LOG_LEVEL_FATAL;
        return true;
    }

    LOGF("LoggerTunnel: settings.level must be one of debug, info, warning, error, or fatal");
    return false;
}

static bool loggertunnelParseOutputMode(loggertunnel_tstate_t *state, const cJSON *settings)
{
    const cJSON *output_mode = cJSON_GetObjectItemCaseSensitive(settings, "output-mode");

    if (output_mode == NULL)
    {
        state->output_mode = kLoggerTunnelOutputModeSplitDirection;
        return true;
    }

    if (! (cJSON_IsString(output_mode) && output_mode->valuestring != NULL))
    {
        LOGF("LoggerTunnel: settings.output-mode must be a string when mode is file or tcp-payload-file");
        return false;
    }

    if (stringCompare(output_mode->valuestring, "per-payload") == 0)
    {
        state->output_mode = kLoggerTunnelOutputModePerPayload;
        return true;
    }

    if (stringCompare(output_mode->valuestring, "split-direction") == 0)
    {
        state->output_mode = kLoggerTunnelOutputModeSplitDirection;
        return true;
    }

    if (stringCompare(output_mode->valuestring, "single-file") == 0)
    {
        state->output_mode = kLoggerTunnelOutputModeSingleFile;
        return true;
    }

    LOGF("LoggerTunnel: settings.output-mode must be one of per-payload, split-direction, or single-file");
    return false;
}

static bool loggertunnelInitializePrefix(loggertunnel_tstate_t *state, node_t *node)
{
    const char *prefix = (node->name != NULL && node->name[0] != '\0') ? node->name : "LoggerTunnel";

    state->file_prefix = stringDuplicate(prefix);
    if (state->file_prefix == NULL)
    {
        LOGF("LoggerTunnel: failed to allocate file prefix");
        return false;
    }

    return true;
}

static bool loggertunnelInitializeFilePaths(loggertunnel_tstate_t *state)
{
    state->up_path   = loggertunnelBuildStaticPath(state->file_prefix, "up.txt");
    state->down_path = loggertunnelBuildStaticPath(state->file_prefix, "down.txt");
    state->all_path  = loggertunnelBuildStaticPath(state->file_prefix, "all.txt");

    if (state->up_path == NULL || state->down_path == NULL || state->all_path == NULL)
    {
        LOGF("LoggerTunnel: failed to allocate output file paths");
        return false;
    }

    return true;
}

tunnel_t *loggertunnelTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(loggertunnel_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &loggertunnelTunnelUpStreamInit;
    t->fnEstU     = &loggertunnelTunnelUpStreamEst;
    t->fnFinU     = &loggertunnelTunnelUpStreamFinish;
    t->fnPayloadU = &loggertunnelTunnelUpStreamPayload;
    t->fnPauseU   = &loggertunnelTunnelUpStreamPause;
    t->fnResumeU  = &loggertunnelTunnelUpStreamResume;

    t->fnInitD    = &loggertunnelTunnelDownStreamInit;
    t->fnEstD     = &loggertunnelTunnelDownStreamEst;
    t->fnFinD     = &loggertunnelTunnelDownStreamFinish;
    t->fnPayloadD = &loggertunnelTunnelDownStreamPayload;
    t->fnPauseD   = &loggertunnelTunnelDownStreamPause;
    t->fnResumeD  = &loggertunnelTunnelDownStreamResume;

    t->onDestroy = &loggertunnelTunnelDestroy;

    const cJSON           *settings = node->node_settings_json;
    loggertunnel_tstate_t *state    = tunnelGetState(t);

    mutexInit(&state->file_mutex);

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("LoggerTunnel: settings must be a non-empty object");
        loggertunnelTunnelDestroy(t);
        return NULL;
    }

    if (! loggertunnelParseMode(state, settings) || ! loggertunnelInitializePrefix(state, node))
    {
        loggertunnelTunnelDestroy(t);
        return NULL;
    }

    if (state->mode == kLoggerTunnelModeLog)
    {
        if (! loggertunnelParseLevel(state, settings))
        {
            loggertunnelTunnelDestroy(t);
            return NULL;
        }
    }
    else
    {
        if (! loggertunnelParseOutputMode(state, settings) || ! loggertunnelInitializeFilePaths(state))
        {
            loggertunnelTunnelDestroy(t);
            return NULL;
        }
    }

    return t;
}
