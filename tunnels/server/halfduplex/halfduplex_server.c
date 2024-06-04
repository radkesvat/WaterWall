#include "halfduplex_server.h"
#include "hmutex.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"

#define i_type hmap_lines_t // NOLINT
#define i_key  hash_t       // NOLINT
#define i_val  line_t *     // NOLINT

enum
{
    kHmapCap = 16 * 4
};

#include "stc/hmap.h"

typedef struct halfduplex_server_state_s
{
    hhybridmutex_t hmap_mutex;
    hmap_lines_t   line_map;

} halfduplex_server_state_t;

typedef struct halfduplex_server_con_state_s
{
    line_t *main_line;
    line_t *upload_line;
    line_t *download_line;
    
} halfduplex_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
    }
    else
    {
        if (c->init)
        {
        }
        else if (c->fin)
        {
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
    }
    else
    {
        if (c->fin)
        {
        }
        else if (c->est)
        {
        }
    }
}

tunnel_t *newHeaderServer(node_instance_context_t *instance_info)
{

    halfduplex_server_state_t *state = malloc(sizeof(halfduplex_server_state_t));
    memset(state, 0, sizeof(halfduplex_server_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHeaderServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyHeaderServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataHeaderServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
