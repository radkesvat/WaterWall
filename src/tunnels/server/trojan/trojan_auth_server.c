#include "trojan_auth_server.h"
#include "hv/hatomic.h"

#define STATE(x) ((trojan_auth_server_state_t *)((x)->state))
#define CSTATE(x) ((trojan_auth_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

#define i_type hmap_users_t
#define i_key sha224_t
#define i_val trojan_user_t

#include "stc/hmap.h"

typedef struct trojan_auth_server_state_s
{
    hloop_t **loops;
    atomic_bool json_locked;

    // settings
    hmap_users_t users;

} trojan_auth_server_state_t;

typedef struct trojan_auth_server_con_state_s
{
    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;

} trojan_auth_server_con_state_t;

static void parse(trojan_auth_server_state_t *state, cJSON *settings)
{

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->Settings (object field) was empty or invalid");
        exit(1);
    }
    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(settings, "users");
    if (!(cJSON_IsArray(users_array) && users_array->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->Settings->Users (array field) was empty or invalid");
        exit(1);
    }

    
}

tunnel_t *newTrojanAuthServer(hloop_t **loops, cJSON *settings)
{
    tunnel_t *t = newTunnel();
    t->state = malloc(sizeof(trojan_auth_server_con_state_t));
    memset(t->state, 0, sizeof(trojan_auth_server_con_state_t));
    STATE(t)->loops = loops;
    parse(STATE(t), settings);

    t->upStream = &TrojanServerUpStream;
    t->packetUpStream = &TrojanServerPacketUpStream;
    t->downStream = &TrojanServerDownStream;
    t->packetDownStream = &TrojanServerPacketDownStream;
}
