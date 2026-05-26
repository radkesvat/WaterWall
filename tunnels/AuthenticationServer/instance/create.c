#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationserverInitializeCallbacks(tunnel_t *t)
{
    t->fnInitU    = &authenticationserverTunnelUpStreamInit;
    t->fnEstU     = &authenticationserverTunnelUpStreamEst;
    t->fnFinU     = &authenticationserverTunnelUpStreamFinish;
    t->fnPayloadU = &authenticationserverTunnelUpStreamPayload;
    t->fnPauseU   = &authenticationserverTunnelUpStreamPause;
    t->fnResumeU  = &authenticationserverTunnelUpStreamResume;

    t->fnInitD    = &authenticationserverTunnelDownStreamInit;
    t->fnEstD     = &authenticationserverTunnelDownStreamEst;
    t->fnFinD     = &authenticationserverTunnelDownStreamFinish;
    t->fnPayloadD = &authenticationserverTunnelDownStreamPayload;
    t->fnPauseD   = &authenticationserverTunnelDownStreamPause;
    t->fnResumeD  = &authenticationserverTunnelDownStreamResume;

    t->onPrepare = &authenticationserverTunnelOnPrepair;
    t->onStart   = &authenticationserverTunnelOnStart;
    t->onDestroy = &authenticationserverTunnelDestroy;
}

static bool authenticationserverParseSettings(authenticationserver_tstate_t *ts, node_t *node)
{
    const cJSON *settings = node->node_settings_json;

    if (nodeHasNext(node))
    {
        LOGF("AuthenticationServer: this node is a chain end and must not have a next node");
        return false;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: AuthenticationServer->settings (object field) : The object was empty or invalid");
        return false;
    }

    if (! getStringFromJsonObject(&ts->db_path, settings, "db-path"))
    {
        LOGF("JSON Error: AuthenticationServer->settings->db-path (string field) : The data was empty or invalid");
        return false;
    }

    int file_save_rate_ms = 0;
    if (! getIntFromJsonObject(&file_save_rate_ms, settings, "file-save-rate-ms") || file_save_rate_ms <= 0)
    {
        LOGF("JSON Error: AuthenticationServer->settings->file-save-rate-ms (positive integer field) : The data was empty or invalid");
        return false;
    }

    ts->file_save_rate_ms = (uint32_t) file_save_rate_ms;
    return true;
}

tunnel_t *authenticationserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(authenticationserver_tstate_t), sizeof(authenticationserver_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }

    authenticationserverInitializeCallbacks(t);

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockinit(&ts->sync_lock);
    ts->sync_lock_created = true;
    recursivemutexInit(&ts->database_mutex);
    ts->database_mutex_created = true;
    atomicStoreRelaxed(&ts->server_index, 1U);

    if (! authenticationserverParseSettings(ts, node))
    {
        authenticationserverTunnelDestroy(t);
        return NULL;
    }

    if (! usersCreate(&ts->users))
    {
        LOGE("AuthenticationServer: failed to create in-memory users database");
        authenticationserverTunnelDestroy(t);
        return NULL;
    }
    ts->users_created = true;

    if (! authenticationserverLoadDatabase(ts))
    {
        LOGE("AuthenticationServer: failed to load users database");
        authenticationserverTunnelDestroy(t);
        return NULL;
    }
    ts->database_loaded = true;

    return t;
}
