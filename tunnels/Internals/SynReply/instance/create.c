#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kSynReplyDefaultTtl = 64
};

tunnel_t *synreplyTunnelCreate(node_t *node)
{
    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGE("SynReply: settings must be an object");
        return NULL;
    }

    const cJSON *source        = cJSON_GetObjectItemCaseSensitive(settings, "reply-source-ip");
    const cJSON *ttl_setting   = cJSON_GetObjectItemCaseSensitive(settings, "ttl");
    const cJSON *fake_checksum = cJSON_GetObjectItemCaseSensitive(settings, "fake-checksum");
    const cJSON *field;
    cJSON_ArrayForEach(field, settings)
    {
        /* Each lookup above selects only the first occurrence of its key. */
        if ((field != source && field != ttl_setting && field != fake_checksum) ||
            ! jsonObjectFieldStringsAreExact(settings, field->string))
        {
            LOGE("SynReply: unknown, duplicate or malformed setting");
            return NULL;
        }
    }

    struct in_addr address = {0};
    if (source != NULL && (! cJSON_IsString(source) || inet_pton(AF_INET, source->valuestring, &address) != 1 ||
                           ! synreplyAddressAllowsReply(address.s_addr)))
    {
        LOGE("SynReply: reply-source-ip must be a unicast IPv4 literal");
        return NULL;
    }

    int64_t ttl = kSynReplyDefaultTtl;
    if (ttl_setting != NULL && ! jsonGetIntegerInRange(ttl_setting, 1, UINT8_MAX, &ttl))
    {
        LOGE("SynReply: ttl must be an integer from 1 to 255");
        return NULL;
    }

    if (fake_checksum != NULL && ! cJSON_IsBool(fake_checksum))
    {
        LOGE("SynReply: fake-checksum must be a boolean");
        return NULL;
    }

    tunnel_t *t = packettunnelCreate(node, sizeof(synreply_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    synreply_tstate_t *state   = tunnelGetState(t);
    state->reply_source_ip     = address.s_addr;
    state->has_reply_source_ip = source != NULL;
    state->ttl                 = (uint8_t) ttl;
    state->fake_checksum       = cJSON_IsTrue(fake_checksum);

    t->fnPayloadU = synreplyTunnelUpStreamPayload;
    t->fnPayloadD = tunnelDefaultDownStreamPayload;
    t->fnFinU     = synreplyTunnelUpStreamFinish;
    t->fnFinD     = synreplyTunnelDownStreamFinish;
    return t;
}
