#include "bridge.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/jsonutils.h"

typedef struct bridge_state_s
{
    bool      mode_upside; // if this node is last node of upstream
    node_t   *pair_node;
    tunnel_t *pair;

} bridge_state_t;

typedef struct bridge_con_state_s
{

} bridge_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    bridge_state_t *state = STATE(self);
    assert(state->mode_upside);

    // swap upstream <-> downstream
    // if (state->pair->upStream == &upStream)
    // {
    //     void *tmp        = self->dw;
    //     *self            = *(state->pair->dw);
    //     self->upStream   = self->downStream;
    //     self->downStream = tmp;
    // }
    // else
    // {
    //     *self            = *(tunnel_t *) (state->pair->downStream);
    //     void *tmp        = self->upStream;
    //     self->upStream   = self->downStream;
    //     self->downStream = tmp;
    // }
    // self->upStream(self, c);

    state->pair->dw->downStream(state->pair->dw, c);
}

static void downStream(tunnel_t *self, context_t *c)
{

    bridge_state_t *state = STATE(self);
    assert(! state->mode_upside);

    // swap upstream <-> downstream
    // if (state->pair->upStream == &upStream)
    // {
    //     void *tmp        = self->up;
    //     *self            = *(state->pair->up);
    //     self->downStream   = self->upStream;
    //     self->upStream = tmp;
    // }
    // else
    // {
    //     *self            = *(tunnel_t *) (state->pair->upStream);
    //     void *tmp        = self->downStream;
    //     self->downStream   = self->upStream;
    //     self->upStream = tmp;
    // }
    // self->downStream(self, c);

    state->pair->up->upStream(state->pair->up, c);
}

tunnel_t *newBridge(node_instance_context_t *instance_info)
{
    const cJSON *settings       = instance_info->node_settings_json;
    char        *pair_node_name = NULL;
    if (! getStringFromJsonObject(&pair_node_name, settings, "pair"))
    {
        LOGF("Bridge: \"pair\" is not provided in json");
        exit(1);
    }

    bridge_state_t *state = malloc(sizeof(bridge_state_t));
    memset(state, 0, sizeof(bridge_state_t));

    hash_t  hash_pairname = CALC_HASH_BYTES(pair_node_name, strlen(pair_node_name));
    node_t *pair_node     = getNode(hash_pairname);
    if (pair_node == NULL)
    {
        LOGF("Bridge: pair node \"%s\" not found", pair_node_name);
        exit(1);
    }
    free(pair_node_name);

    state->pair_node   = pair_node;
    state->mode_upside = instance_info->node->next == NULL;
    tunnel_t *t        = newTunnel();

    if (pair_node->instance)
    {
        state->pair                = pair_node->instance;
        bridge_state_t *pair_state = STATE(pair_node->instance);
        pair_state->pair           = t;
    }

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    return t;
}

api_result_t apiBridge(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyBridge(tunnel_t *self)
{
    (void) (self);

    return NULL;
}
tunnel_metadata_t getMetadataBridge()
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}