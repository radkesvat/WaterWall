#include "trojan_auth_server.h"
#include "loggers/network_logger.h"
#include "utils/userutils.h"
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
    trojan_user_t *t_user;

    
    ud_t traffic;
    ud_t speed_limit;
    
   


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
    const cJSON *elment = NULL;


    unsigned int total_parsed = 0;
    unsigned int total_users = 0;
    cJSON_ArrayForEach(elment, users_array)
    {
        user_t* user = parseUser(elment);
        if (user ==NULL)
        {
            LOGW("TrojanAuthServer: 1 User json-parse failed, plase check the json");

        }else{
            total_parsed++;
        }
   

        total_users++;
    }
    LOGI("TrojanAuthServer: %zu users parsed (out of total %zu) and can connect",total_parsed,total_users);

    
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
