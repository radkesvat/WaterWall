#include "connector.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/stringutils.h"

typedef struct connector_state_s
{
    tunnel_t *tcp_connector;
    tunnel_t *udp_connector;

} connector_state_t;

typedef struct connector_con_state_s
{
    void *_;
} connector_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    connector_state_t *state = TSTATE(self);

    switch ((c->line->dest_ctx.address_protocol))
    {
    default:
    case kSapTcp:
        state->tcp_connector->upStream(state->tcp_connector, c);
        break;

    case kSapUdp:
        state->udp_connector->upStream(state->udp_connector, c);
        break;
    }
}
static void downStream(tunnel_t *self, context_t *c)
{
    self->dw->downStream(self->dw, c);
}

tunnel_t *newConnector(node_instance_context_t *instance_info)
{
    connector_state_t *state = memoryAllocate(sizeof(connector_state_t));
    memorySet(state, 0, sizeof(connector_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Connector->settings (object field) : The object was empty or invalid");
        return NULL;
    }
    node_t *tcp_outbound_node  = nodemanagerNewNode();
    node_t *udp_outbound_node  = nodemanagerNewNode();
    tcp_outbound_node->name    = stringConcat(instance_info->node->name, "_tcp_outbound");
    tcp_outbound_node->type    = stringDuplicate("TcpConnector");
    tcp_outbound_node->version = instance_info->node->version;
    udp_outbound_node->name    = stringConcat(instance_info->node->name, "_udp_outbound");
    udp_outbound_node->type    = stringDuplicate("UdpConnector");
    udp_outbound_node->version = instance_info->node->version;
    nodemanagerCreateNodeInstance(instance_info->node_manager_config, tcp_outbound_node, settings);
    nodemanagerCreateNodeInstance(instance_info->node_manager_config, udp_outbound_node, settings);
    nodemanagerRunNode(instance_info->node_manager_config, tcp_outbound_node, instance_info->chain_index);
    nodemanagerRunNode(instance_info->node_manager_config, udp_outbound_node, instance_info->chain_index);
    state->tcp_connector = tcp_outbound_node->instance;
    state->udp_connector = udp_outbound_node->instance;

    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    tunnelBindDown(t, state->tcp_connector);
    tunnelBindDown(t, state->udp_connector);

    return t;
}
api_result_t apiConnector(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyConnector(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataConnector(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
