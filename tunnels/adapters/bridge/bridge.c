#include "bridge.h"
#include "managers/node_manager.h"
#include "loggers/network_logger.h"


#define STATE(x) ((bridge_state_t *)((x)->state))
#define CSTATE(x) ((bridge_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct bridge_state_s
{
    bool initialized;
    bool mode_upside; // this node is last node of upstream
    node_t *pair_node;
    tunnel_t *pair;

} bridge_state_t;

typedef struct bridge_con_state_s
{

} bridge_con_state_t;

static void secondary_init(tunnel_t *self, bridge_state_t *state)
{
    if (state->pair_node->instance == NULL)
    {
        LOGF("Bridge: the pair node is not running");
        exit(1);
    }
    if (!state->mode_upside && self->dw != NULL)
    {
        LOGF("Bridge: misconfiguration, bridge only exists at the start or end of a chain");
        exit(1);
    }
    state->pair = state->pair_node->instance;
    state->initialized = true;
}
static void upStream(tunnel_t *self, context_t *c)
{
    bridge_state_t *state = STATE(self);
    if (!state->initialized)
        secondary_init(self,state);
    if (state->mode_upside)
        state->pair->downStream(state->pair, c);
    else
        self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    bridge_state_t *state = STATE(self);
    if (!state->initialized)
        secondary_init(self,state);
    if (state->mode_upside)
        self->dw->downStream(self->dw, c);
    else
        state->pair->upStream(state->pair, c);
}

static void BridgeUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void BridgePacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void BridgeDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void BridgePacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newBridge(node_instance_context_t *instance_info)
{
    const cJSON *settings = instance_info->node_settings_json;
    char *pair_node_name = NULL;
    if (!getStringFromJsonObject(&pair_node_name, settings, "pair"))
    {
        LOGF("Bridge: \"pair\" is not provided in json");
        exit(1);
    }

    bridge_state_t *state = malloc(sizeof(bridge_state_t));
    memset(state, 0, sizeof(bridge_state_t));

    hash_t hash_pairname = CALC_HASH_BYTES(pair_node_name, strlen(pair_node_name));    
    node_t *pair_node = getNode(hash_pairname);
    if (pair_node == NULL)
    {
        LOGF("Bridge: pair node \"%s\" not found", pair_node_name);
        exit(1);
    }
    free(pair_node_name);
    state->pair_node = pair_node;

    state->mode_upside = instance_info->self_node_handle->next == NULL;


    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &BridgeUpStream;
    t->packetUpStream = &BridgePacketUpStream;
    t->downStream = &BridgeDownStream;
    t->packetDownStream = &BridgePacketDownStream;
    return t;
}

api_result_t apiBridge(tunnel_t *self, char *msg)
{
    (void)(self); (void)(msg); return (api_result_t){0}; // TODO
}

tunnel_t *destroyBridge(tunnel_t *self)
{
    return NULL;
}
tunnel_metadata_t getMetadataBridge()
{
    return (tunnel_metadata_t){.version = 0001, .flags = TFLAG_ROUTE_STARTER};
}