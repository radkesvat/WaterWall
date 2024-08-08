#include "ip_routing_table.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"
#include "utils/sockutils.h"

typedef struct
{
    union {
        struct in_addr  ip4;
        struct in6_addr ip6;
    } ip;

    union {
        struct in_addr  mask4;
        struct in6_addr mask6;
    } mask;

    tunnel_t *next;
    bool      v4;

} routing_rule_t;

typedef struct layer3_ip_overrider_state_s
{

    routing_rule_t routes[8];
    uint8_t        routes_len;

} layer3_ip_overrider_state_t;

typedef struct layer3_ip_overrider_con_state_s
{
    void *_;
} layer3_ip_overrider_con_state_t;

static void upStreamSrcMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    self->up->upStream(self->up, c);
}

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};

static void upStreamDestMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    for (unsigned int i = 0; i < state->routes_len; i++)
    {
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    self->dw->downStream(self->dw, c);
}

static routing_rule_t parseRule(const cJSON *rule_obj)
{
    char *temp = NULL;

    if (! getStringFromJsonObject(&(temp), rule_obj, "ip") || ! verifyIpCdir(temp, getNetworkLogger()))
    {
        LOGF("JSON Error: Layer3IpRoutingTable->settings->rules invalid rule");
        exit(1);
    }

    routing_rule_t rule  = {0};
    int            ipver = parseIPWithSubnetMask((struct in6_addr *) &rule.ip, temp, (struct in6_addr *) &rule.mask);
    if (ipver != 4 && ipver != 6)
    {
        LOGF("JSON Error: Layer3IpRoutingTable->settings->rules rule parse failed");
    }
    rule.v4 = ipver == 4;
    globalFree(temp);
    return rule;
}

tunnel_t *newLayer3IpRoutingTable(node_instance_context_t *instance_info)
{
    layer3_ip_overrider_state_t *state = globalMalloc(sizeof(layer3_ip_overrider_state_t));
    memset(state, 0, sizeof(layer3_ip_overrider_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3IpRoutingTable->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    dynamic_value_t mode_dv =
        parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "dest-override", "src-override");

    if ((int) mode_dv.status != kDvsDestMode && (int) mode_dv.status != kDvsSourceMode)
    {
        LOGF("Layer3IpRoutingTable: Layer3IpRoutingTable->settings->mode (string field)  mode is not set or invalid, "
             "do you "
             "want to filter based on source ip or dest ip?");
        exit(1);
    }

    const cJSON *rules = cJSON_GetObjectItemCaseSensitive(settings, "rules");
    if (! cJSON_IsArray(rules))
    {
        LOGF("JSON Error: Layer3IpRoutingTable->settings->rules (array field) : The arary was empty or invalid");
        exit(1);
    }

    unsigned int i         = 0;
    const cJSON *list_item = NULL;
    cJSON_ArrayForEach(list_item, rules)
    {
        state->routes[i++] = parseRule(list_item);
    }
    if (i == 0)
    {
        LOGF("Layer3IpRoutingTable: no rules");
        exit(1);
    }
    if (i > ARRAY_SIZE(state->routes))
    {
        LOGF("Layer3IpRoutingTable: too much rules");
        exit(1);
    }



    tunnel_t *t = newTunnel();

    t->state      = state;
    t->upStream   = ((int) mode_dv.status == kDvsDestMode) ? &upStreamDestMode : &upStreamSrcMode;
    t->downStream = &downStream;

    return t;
}
api_result_t apiLayer3IpRoutingTable(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3IpRoutingTable(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3IpRoutingTable(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
