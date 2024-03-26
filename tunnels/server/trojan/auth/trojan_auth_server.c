#include "trojan_auth_server.h"
#include "managers/node_manager.h"
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
    tunnel_t *fallback;
    int fallback_delay;
    hmap_users_t users;

} trojan_auth_server_state_t;

typedef struct trojan_auth_server_con_state_s
{
    bool authenticated;
    bool init_sent;

} trojan_auth_server_con_state_t;

struct timer_eventdata
{
    tunnel_t *self;
    context_t *c;
};
static struct timer_eventdata *newTimerData(tunnel_t *self, context_t *c)
{
    struct timer_eventdata *result = malloc(sizeof(struct timer_eventdata));
    result->self = self;
    result->c = c;
    return result;
}

static void on_fallback_timer(htimer_t *timer)
{
    struct timer_eventdata *data = hevent_userdata(timer);
    tunnel_t *self = data->self;
    trojan_auth_server_state_t *state = STATE(self);
    context_t *c = data->c;

    free(data);
    htimer_del(timer);

    if (!ISALIVE(c))
    {
        if (c->payload != NULL)
            DISCARD_CONTEXT(c);
        destroyContext(c);
        return;
    }
    state->fallback->upStream(state->fallback, c);
}

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
                // struct timeval tv1, tv2;
                // gettimeofday(&tv1, NULL);
                {

                    // the payload must not come buffeered here (gfw can do this but not the client)
                    // so , if its incomplete we go to fallback!
                    size_t len = bufLen(c->payload);
                    if (len < (sizeof(sha224_hex_t) + CRLF_LEN))
                    {
                        // invalid protocol
                        LOGW("TrojanAuthServer: detected non trojan protocol, rejected");
                        goto failed;
                    }
                    // save time easily
                    if (rawBuf(c->payload)[sizeof(sha224_hex_t)] != '\r' || rawBuf(c->payload)[sizeof(sha224_hex_t) + 1] != '\n')
                    {
                        LOGW("TrojanAuthServer: detected non trojan protocol, rejected");
                        goto failed;
                    }

                    hash_t kh = calcHashLen(rawBuf(c->payload), sizeof(sha224_hex_t));

                    hmap_users_t_iter find_result = hmap_users_t_find(&(state->users), kh);
                    if (find_result.ref == hmap_users_t_end(&(state->users)).ref)
                    {
                        // user not in database
                        LOGW("TrojanAuthServer: a trojan-user rejecetd because not found in database");
                        goto failed;
                    }
                    trojan_user_t *tuser = (find_result.ref->second);
                    if (!tuser->user.enable)
                    {
                        // user disabled
                        LOGW("TrojanAuthServer: user \"%s\" rejecetd because not enabled", tuser->user.name);

                        goto failed;
                    }
                    LOGD("TrojanAuthServer: user \"%s\" accepted", tuser->user.name);
                    cstate->authenticated = true;
                    context_t *init_ctx = newInitContext(c->line);
                    init_ctx->src_io = c->src_io;
                    cstate->init_sent = true;
                    self->up->upStream(self->up, init_ctx);
                    if (!ISALIVE(c))
                    {
                        DISCARD_CONTEXT(c);
                        destroyContext(c);
                        return;
                    }

                    shiftr(c->payload, sizeof(sha224_hex_t) + CRLF_LEN);
                    self->up->upStream(self->up, c);
                }
                // gettimeofday(&tv2, NULL);

                // double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 + (double)(tv2.tv_sec - tv1.tv_sec);
                // LOGD("Auth: took %lf sec", time_spent);
                return;
            }
            else
                goto failed;
        }
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(trojan_auth_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(trojan_auth_server_con_state_t));
            trojan_auth_server_con_state_t *cstate = CSTATE(c);
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = CSTATE(c)->init_sent;
            bool auth = CSTATE(c)->authenticated;
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            if (init_sent)
                if (auth)
                    self->up->upStream(self->up, c);
                else
                    state->fallback->upStream(state->fallback, c);
            else
                destroyContext(c);
        }
    }

    return;
failed:;
    if (state->fallback != NULL)
        goto fallback;

disconnect:;
    DISCARD_CONTEXT(c);
    free(CSTATE(c));
    CSTATE_MUT(c) = NULL;
    context_t *reply = newFinContext(c->line);
    destroyContext(c);
    self->dw->downStream(self->dw, reply);
    return;
fallback:;
    trojan_auth_server_con_state_t *cstate = CSTATE(c);
    if (!cstate->init_sent)
    {
        context_t *init_ctx = newInitContext(c->line);
        init_ctx->src_io = c->src_io;
        cstate->init_sent = true;

        state->fallback->upStream(state->fallback, init_ctx);
        if (!ISALIVE(c))
        {
            DISCARD_CONTEXT(c);
            destroyContext(c);
            return;
        }
    }
    if (state->fallback_delay <= 0)
    {
        state->fallback->upStream(state->fallback, c);
    }
    else
    {
        htimer_t *t = htimer_add(c->line->loop, on_fallback_timer, state->fallback_delay, 1);
        hevent_set_userdata(t, newTimerData(self, c));
    }
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
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

static void parse(tunnel_t *t, cJSON *settings, size_t chain_index)
{
    trojan_auth_server_state_t *state = t->state;
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

    char *fallback_node = NULL;
    if (!getStringFromJsonObject(&fallback_node, settings, "fallback"))
    {
        LOGW("TrojanAuthServer: no fallback provided in json, standard trojan requires fallback");
    }
    else
    {

        getIntFromJsonObject(&(state->fallback_delay), settings, "fallback-intence-delay");
        if (state->fallback_delay < 0)
            state->fallback_delay = 0;

        LOGD("TrojanAuthServer: accessing fallback node");

        hash_t hash_next = calcHashLen(fallback_node, strlen(fallback_node));
        node_t *next_node = getNode(hash_next);
        if (next_node == NULL)
        {
            LOGF("TrojanAuthServer: fallback node not found");
            exit(1);
        }
        if (next_node->instance == NULL)
        {
            runNode(next_node, chain_index + 1);
        }
        else
        {
        }
        state->fallback = next_node->instance;

        if (state->fallback != NULL)
        {
            state->fallback->dw = t;
        }
    }
    free(fallback_node);
}

tunnel_t *newTrojanAuthServer(node_instance_context_t *instance_info)
{
    trojan_auth_server_state_t *state = malloc(sizeof(trojan_auth_server_state_t));
    memset(state, 0, sizeof(trojan_auth_server_state_t));
    state->users = hmap_users_t_with_capacity(VEC_CAP);
    cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->settings (object field) : The object was empty or invalid.");
        return NULL;
    }
    tunnel_t *t = newTunnel();
    t->state = state;

    t->upStream = &trojanAuthServerUpStream;
    t->packetUpStream = &trojanAuthServerPacketUpStream;
    t->downStream = &trojanAuthServerDownStream;
    t->packetDownStream = &trojanAuthServerPacketDownStream;
    parse(t, settings, instance_info->chain_index);

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiTrojanAuthServer(tunnel_t *self, char *msg)
{
    LOGE("trojan-auth-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyTrojanAuthServer(tunnel_t *self)
{
    LOGE("trojan-auth-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataTrojanAuthServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
