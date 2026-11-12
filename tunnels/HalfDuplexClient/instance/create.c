#include "structure.h"

#include "loggers/network_logger.h"

static bool halfduplexclientReadPaths(node_t *node, halfduplexclient_tstate_t *ts)
{
    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("HalfDuplexClient: settings must be an object");
        return false;
    }
    const cJSON *upload   = cJSON_GetObjectItemCaseSensitive(settings, "upload");
    const cJSON *download = cJSON_GetObjectItemCaseSensitive(settings, "download");
    if (upload == NULL && download == NULL)
    {
        if (node->next == NULL || node->next[0] == '\0' || ! jsonObjectFieldStringsAreExact(node->node_json, "next"))
        {
            LOGF("HalfDuplexClient: next is required when settings.upload and settings.download are omitted");
            return false;
        }
        return true;
    }
    if (! cJSON_IsString(upload) || ! cJSON_IsString(download) || upload->valuestring == NULL ||
        download->valuestring == NULL || upload->valuestring[0] == '\0' || download->valuestring[0] == '\0' ||
        ! jsonObjectFieldStringsAreExact(settings, "upload") || ! jsonObjectFieldStringsAreExact(settings, "download"))
    {
        LOGF("HalfDuplexClient: settings.upload and settings.download must both be nonempty node names");
        return false;
    }
    if (node->next != NULL || cJSON_GetObjectItemCaseSensitive(node->node_json, "next") != NULL)
    {
        LOGF("HalfDuplexClient: next must be omitted when settings.upload and settings.download are supplied");
        return false;
    }
    ts->upload_node   = nodemanagerGetConfigNodeByName(node->node_manager_config, upload->valuestring);
    ts->download_node = nodemanagerGetConfigNodeByName(node->node_manager_config, download->valuestring);
    if (ts->upload_node == NULL || ts->download_node == NULL)
    {
        LOGF("HalfDuplexClient: configured upload or download node was not found");
        return false;
    }
    if (ts->upload_node == node || ts->download_node == node)
    {
        LOGF("HalfDuplexClient: upload/download nodes must not point back to this node");
        return false;
    }
    return true;
}

tunnel_t *halfduplexclientTunnelCreate(node_t *node)
{
    assert(node != NULL);
    tunnel_t *t = tunnelCreate(node, kTunnelStateSize, kLineStateSize);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &halfduplexclientTunnelUpStreamInit;
    t->fnFinU     = &halfduplexclientTunnelUpStreamFinish;
    t->fnPayloadU = &halfduplexclientTunnelUpStreamPayload;
    t->fnPauseU   = &halfduplexclientTunnelUpStreamPause;
    t->fnResumeU  = &halfduplexclientTunnelUpStreamResume;
    t->fnEstD     = &halfduplexclientTunnelDownStreamEst;
    t->fnFinD     = &halfduplexclientTunnelDownStreamFinish;
    t->fnPayloadD = &halfduplexclientTunnelDownStreamPayload;
    t->fnPauseD   = &halfduplexclientTunnelDownStreamPause;
    t->fnResumeD  = &halfduplexclientTunnelDownStreamResume;
    t->onChain    = &halfduplexclientTunnelOnChain;

    if (! halfduplexclientReadPaths(node, tunnelGetState(t)))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
