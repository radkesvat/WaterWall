#include "connector.h"
#include "loggers/network_logger.h"
#include "types.h"
#include "utils/sockutils.h"

static void tcpUpStream(tunnel_t *self, context_t *c)
{
}
static void tcpDownStream(tunnel_t *self, context_t *c)
{
}
static void udpUpStream(tunnel_t *self, context_t *c)
{
}
static void udpDownStream(tunnel_t *self, context_t *c)
{
}

static void upStream(tunnel_t *self, context_t *c)
{
}
static void downStream(tunnel_t *self, context_t *c)
{
}

tunnel_t *newConnector(node_instance_context_t *instance_info)
{
    connector_state_t *state = malloc(sizeof(connector_state_t));
    memset(state, 0, sizeof(connector_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Connector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);
    return t;
}
api_result_t apiConnector(tunnel_t *self,const char *msg)
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
tunnel_metadata_t getMetadataConnector()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}