#include "listener.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/stringutils.h"
#include <stdint.h>
#include <time.h>

typedef struct listener_state_s
{
    node_t   *tcp_inbound_node;
    node_t   *udp_inbound_node;
    tunnel_t *tcp_listener;
    tunnel_t *udp_listener;

} listener_state_t;

typedef struct listener_con_state_s
{
    void*_;
} listener_con_state_t;

// set function pointers baby))
static void upStream(tunnel_t *self, context_t *c);

static void firstUpStream(tunnel_t *self, context_t *c)
{

    listener_state_t *state = TSTATE(self);
    state->tcp_listener     = state->tcp_inbound_node->instance;
    state->udp_listener     = state->udp_inbound_node->instance;
    self->upStream          = upStream;
    upStream(self, c);
}
static void upStream(tunnel_t *self, context_t *c)
{
    self->up->upStream(self->up, c);
}
static void downStream(tunnel_t *self, context_t *c)
{
    listener_state_t *state = TSTATE(self);

    switch ((c->line->src_ctx.address_protocol))
    {
    default:
    case kSapTcp:
        state->tcp_listener->downStream(state->tcp_listener, c);
        break;

    case kSapUdp:
        state->udp_listener->downStream(state->udp_listener, c);
        break;
    }
}

tunnel_t *newListener(node_instance_context_t *instance_info)
{
    listener_state_t *state = globalMalloc(sizeof(listener_state_t));
    memset(state, 0, sizeof(listener_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Listener->settings (object field) : The object was empty or invalid");
        return NULL;
    }
    node_t *tcp_inbound_node  = newNode();
    node_t *udp_inbound_node  = newNode();
    tcp_inbound_node->name    = concat(instance_info->node->name, "_tcp_inbound");
    tcp_inbound_node->type    = strdup("TcpListener");
    tcp_inbound_node->version = instance_info->node->version;
    tcp_inbound_node->next    = instance_info->node->name;

    udp_inbound_node->name    = concat(instance_info->node->name, "_udp_inbound");
    udp_inbound_node->type    = strdup("UdpListener");
    udp_inbound_node->version = instance_info->node->version;
    udp_inbound_node->next    = instance_info->node->name;

    state->tcp_inbound_node = tcp_inbound_node;
    state->udp_inbound_node = udp_inbound_node;
    // this is enough, node map will run these and perform chaining
    registerNode(instance_info->node_manager_config,tcp_inbound_node, settings);
    registerNode(instance_info->node_manager_config,udp_inbound_node, settings);


    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &firstUpStream;
    t->downStream = &downStream;
    
    return t;
}
api_result_t apiListener(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}
tunnel_t *destroyListener(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataListener(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}
