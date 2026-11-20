#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *synreplyTunnelCreate(node_t *node)
{
    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGE("SynReply: settings must be an object");
        return NULL;
    }

    const char    *key     = "reply-source-ip";
    const cJSON   *source  = settings != NULL ? settings->child : NULL;
    struct in_addr address = {0};
    if (source != NULL)
    {
        if (source->string == NULL || strcmp(source->string, key) != 0 || source->next != NULL)
        {
            LOGE("SynReply: settings may contain only one reply-source-ip field");
            return NULL;
        }
        if (! cJSON_IsString(source) || ! jsonObjectFieldStringsAreExact(settings, key) ||
            inet_pton(AF_INET, source->valuestring, &address) != 1 || ! synreplyAddressAllowsReply(address.s_addr))
        {
            LOGE("SynReply: reply-source-ip must be a unicast IPv4 literal");
            return NULL;
        }
    }

    tunnel_t *t = packettunnelCreate(node, sizeof(synreply_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    synreply_tstate_t *state   = tunnelGetState(t);
    state->reply_source_ip     = address.s_addr;
    state->has_reply_source_ip = source != NULL;

    t->fnPayloadU = synreplyTunnelUpStreamPayload;
    t->fnPayloadD = tunnelDefaultDownStreamPayload;
    t->fnFinU     = synreplyTunnelUpStreamFinish;
    t->fnFinD     = synreplyTunnelDownStreamFinish;
    return t;
}
