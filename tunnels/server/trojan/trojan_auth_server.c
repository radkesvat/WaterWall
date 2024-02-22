#include "trojan_auth_server.h"
#include "loggers/network_logger.h"
#include "utils/userutils.h"
#include "utils/stringutils.h"
#include "hv/hatomic.h"

#define STATE(x) ((trojan_auth_server_state_t *)((x)->state))
#define CSTATE(x) ((trojan_auth_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

#define i_type hmap_users_t
#define i_key hash_t
#define i_val trojan_user_t *

#define VEC_CAP 100
#define CRLF_LEN 2

#include "stc/hmap.h"

typedef struct trojan_auth_server_state_s
{
    config_file_t *config_file;

    hmap_users_t users;

} trojan_auth_server_state_t;

typedef struct trojan_auth_server_con_state_s
{
    trojan_user_t *t_user;
    bool authenticated;

} trojan_auth_server_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{
    trojan_auth_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        trojan_auth_server_con_state_t *cstate = CSTATE(c);
        if (cstate->authenticated)
        {
            self->up->upStream(self->up, c);
            return;
        }
        else
        {
            if (c->first)
            {
                // they payload must not come buffeered here (gfw can do this but not the client)
                // so , if its incomplete we go to fallback!
                size_t len = bufLen(c->payload);
                if (len < (sizeof(sha224_hex_t)))
                {
                    // invalid protocol
                    //  TODO fallback
                    LOGW("TrojanAuthServer: detected non trojan protocol, rejected");
                    DISCARD_CONTEXT(c);
                    goto failed;
                }
                hash_t kh = calcHashLen(rawBuf(c->payload), sizeof(sha224_hex_t));

                hmap_users_t_iter find_result = hmap_users_t_find(&(state->users), kh);
                if (find_result.ref == hmap_users_t_end(&(state->users)).ref)
                {
                    // user not in database
                    // TODO fallback
                    LOGW("TrojanAuthServer: a trojan-user rejecetd because not found in database");
                    DISCARD_CONTEXT(c);
                    goto failed;
                }
                trojan_user_t *tuser = (find_result.ref->second);
                if (!tuser->user.enable)
                {
                    // user disabled
                    // TODO fallback
                    LOGW("TrojanAuthServer: user \"%s\" rejecetd because not enabled", tuser->user.name);
                    DISCARD_CONTEXT(c);
                    goto failed;
                }
                LOGD("TrojanAuthServer: user \"%s\" accepted", tuser->user.name);
                context_t *init_ctx = newContext(c->line);
                init_ctx->init = true;
                self->up->upStream(self->up, init_ctx);
                if (!ISALIVE(c))
                {
                    DISCARD_CONTEXT(c);
                    return;
                }

                shiftr(c,CRLF_LEN);
                self->up->upStream(self->up, c);
                return;
            }
            else
            {
                DISCARD_CONTEXT(c);
                goto failed;
            }
        }
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(trojan_auth_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(trojan_auth_server_con_state_t));
            trojan_auth_server_con_state_t *cstate = CSTATE(c);
        }
    }

    return;
failed:
    context_t *reply = newContext(c->line);
    reply->fin = true;
    destroyContext(c);
    self->dw->downStream(self->dw, reply);
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    self->dw->downStream(self->dw, c);

    return;
}

static void trojanAuthServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void trojanAuthServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void trojanAuthServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void trojanAuthServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

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
    cJSON *element = NULL;

    unsigned int total_parsed = 0;
    unsigned int total_users = 0;
    cJSON_ArrayForEach(element, users_array)
    {
        user_t *user = parseUserFromJsonObject(element);
        if (user == NULL)
        {
            LOGW("TrojanAuthServer: 1 User json-parse failed, please check the json");
        }
        else
        {
            total_parsed++;
            trojan_user_t *tuser = malloc(sizeof(trojan_user_t));
            memset(tuser, 0, sizeof(trojan_user_t));
            tuser->user = *user;
            free(user);
            sha224(tuser->user.uid, strlen(tuser->user.uid), &(tuser->hash_user[0]));

            for (int i = 0; i < sizeof(sha224_t); i++)
            {
                sprintf(&(tuser->hash_hexed_user[i * 2]), "%02x", (unsigned char)(tuser->hash_user[i]));
            }
            // 640f8fd293ea546e483060cce622d7f9ab96026d6af84a4333f486f9
            LOGD("TrojanAuthServer: user \"%s\" parsed, sha224: %.12s...", tuser->user.name, tuser->hash_hexed_user);

            tuser->komihash_of_hex = calcHashLen(tuser->hash_hexed_user, sizeof(sha224_hex_t));

            hmap_users_t_push(&(state->users), (hmap_users_t_value){tuser->komihash_of_hex, tuser});
        }

        total_users++;
    }
    LOGI("TrojanAuthServer: %zu users parsed (out of total %zu) and can connect", total_parsed, total_users);
}

tunnel_t *newTrojanAuthServer(node_instance_context_t *instance_info)
{
    trojan_auth_server_state_t *state = malloc(sizeof(trojan_auth_server_state_t));
    memset(state, 0, sizeof(trojan_auth_server_state_t));
    state->users = hmap_users_t_with_capacity(VEC_CAP);
    cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: OpenSSLServer->settings (object field) : The object was empty or invalid.");
        return NULL;
    }

    parse(state, settings);

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &trojanAuthServerUpStream;
    t->packetUpStream = &trojanAuthServerPacketUpStream;
    t->downStream = &trojanAuthServerDownStream;
    t->packetDownStream = &trojanAuthServerPacketDownStream;
    atomic_thread_fence(memory_order_release);
    return t;
}
void apiTrojanAuthServer(tunnel_t *self, char *msg)
{
    LOGE("trojan-auth-server API NOT IMPLEMENTED"); // TODO
}

tunnel_t *destroyTrojanAuthServer(tunnel_t *self)
{
    LOGE("trojan-auth-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
