#include "structure.h"

#include "loggers/network_logger.h"

static bool halfduplexserverReadPair(node_t *node, halfduplexserver_tstate_t *ts)
{
    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("HalfDuplexServer: settings must be an object");
        return false;
    }
    const cJSON *pair = cJSON_GetObjectItemCaseSensitive(settings, "pair");
    if (pair == NULL)
    {
        if (node->next == NULL || node->next[0] == '\0' || ! jsonObjectFieldStringsAreExact(node->node_json, "next"))
        {
            LOGF("HalfDuplexServer: next is required when settings.pair is omitted");
            return false;
        }
        return true;
    }
    if (! cJSON_IsString(pair) || pair->valuestring == NULL || pair->valuestring[0] == '\0' ||
        ! jsonObjectFieldStringsAreExact(settings, "pair"))
    {
        LOGF("HalfDuplexServer: settings.pair must be a nonempty node name");
        return false;
    }
    if (node->next != NULL || cJSON_GetObjectItemCaseSensitive(node->node_json, "next") != NULL)
    {
        LOGF("HalfDuplexServer: next must be omitted when settings.pair is supplied");
        return false;
    }
    node_t *primary = nodemanagerGetConfigNodeByName(node->node_manager_config, pair->valuestring);
    if (primary == NULL || primary == node || primary->type == NULL || node->type == NULL ||
        primary->hash_type != node->hash_type || stringCompare(primary->type, node->type) != 0)
    {
        LOGF("HalfDuplexServer: pair must name another HalfDuplexServer in this configuration");
        return false;
    }
    if (cJSON_GetObjectItemCaseSensitive(primary->node_settings_json, "pair") != NULL)
    {
        LOGF("HalfDuplexServer: pair must refer directly to a primary without settings.pair");
        return false;
    }
    ts->pair_node = primary;
    return true;
}

tunnel_t *halfduplexserverTunnelCreate(node_t *node)
{
    assert(node != NULL);
    tunnel_t *t = tunnelCreate(node, sizeof(halfduplexserver_tstate_t), sizeof(halfduplexserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    halfduplexserver_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &halfduplexserverTunnelUpStreamInit;
    t->fnEstU     = &halfduplexserverTunnelUpStreamEst;
    t->fnFinU     = &halfduplexserverTunnelUpStreamFinish;
    t->fnPayloadU = &halfduplexserverTunnelUpStreamPayload;
    t->fnPauseU   = &halfduplexserverTunnelUpStreamPause;
    t->fnResumeU  = &halfduplexserverTunnelUpStreamResume;
    t->fnEstD     = &halfduplexserverTunnelDownStreamEst;
    t->fnFinD     = &halfduplexserverTunnelDownStreamFinish;
    t->fnPayloadD = &halfduplexserverTunnelDownStreamPayload;
    t->fnPauseD   = &halfduplexserverTunnelDownStreamPause;
    t->fnResumeD  = &halfduplexserverTunnelDownStreamResume;

    t->onChain   = &halfduplexserverTunnelOnChain;
    t->onDestroy = &halfduplexserverTunnelDestroy;

    ts->upload_line_map   = hmap_cons_t_init();
    ts->download_line_map = hmap_cons_t_init();

    if (! halfduplexserverReadPair(node, ts))
    {
        halfduplexserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    if (ts->pair_node == NULL)
    {
        ts->owner = t;
        if (UNLIKELY(! mutexTryInit(&ts->pending_line_maps_mutex)))
        {
            halfduplexserverTunnelDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
        ts->pending_line_maps_mutex_initialized = true;

        const bool download_reserved = hmap_cons_t_reserve(&ts->download_line_map, kHmapCap);
        const bool upload_reserved   = hmap_cons_t_reserve(&ts->upload_line_map, kHmapCap);
        assert(download_reserved && hmap_cons_t_capacity(&ts->download_line_map) >= kHmapCap);
        assert(upload_reserved && hmap_cons_t_capacity(&ts->upload_line_map) >= kHmapCap);
        discard download_reserved;
        discard upload_reserved;
    }

    tunnel_t *pipe_tunnel = pipetunnelCreate(t);
    if (! pipe_tunnel)
    {
        // The wrapper never took ownership, so the child is still this call's.
        halfduplexserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    ts->wrapper = pipe_tunnel;
    return pipe_tunnel;
}
