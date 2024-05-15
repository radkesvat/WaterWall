#include "trojan_auth_server.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/jsonutils.h"
#include "utils/userutils.h"

#define i_type hmap_users_t    // NOLINT
#define i_key  hash_t          // NOLINT
#define i_val  trojan_user_t * // NOLINT

enum
{
    kVecCap  = 100,
    kCRLFLen = 2
};

#include "stc/hmap.h"

typedef struct trojan_auth_server_state_s
{
    config_file_t *config_file;
    tunnel_t      *fallback;
    int            fallback_delay;
    hmap_users_t   users;

} trojan_auth_server_state_t;

typedef struct trojan_auth_server_con_state_s
{
    bool authenticated;
    bool init_sent;

} trojan_auth_server_con_state_t;

struct timer_eventdata
{
    tunnel_t  *self;
    context_t *c;
};
static struct timer_eventdata *newTimerData(tunnel_t *self, context_t *c)
{
    struct timer_eventdata *result = malloc(sizeof(struct timer_eventdata));
    result->self                   = self;
    result->c                      = c;
    return result;
}

static void onFallbackTimer(htimer_t *timer)
{
    struct timer_eventdata     *data  = hevent_userdata(timer);
    tunnel_t                   *self  = data->self;
    trojan_auth_server_state_t *state = STATE(self);
    context_t                  *c     = data->c;

    free(data);
    htimer_del(timer);

    if (! isAlive(c->line))
    {
        if (c->payload != NULL)
        {
            reuseContextBuffer(c);
        }
        destroyContext(c);
        return;
    }
    state->fallback->upStream(state->fallback, c);
}

static void upStream(tunnel_t *self, context_t *c)
{
    trojan_auth_server_state_t     *state  = STATE(self);
    trojan_auth_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->authenticated)
        {
            self->up->upStream(self->up, c);
            return;
        }

        if (c->first)
        {
            // struct timeval tv1, tv2;
            // gettimeofday(&tv1, NULL);
            {

                // beware! trojan auth will not use stream buffer, at least the auth chunk must come in first sequence
                // the payload must not come buffeered here (gfw can do this and detect trojan authentication
                // but the client is not supposed to send small segments)
                // so , if its incomplete we go to fallback!
                // this is also mentioned in standard trojan docs (first packet also contains part of final payload)
                size_t len = bufLen(c->payload);
                if (len < (sizeof(sha224_hex_t) + kCRLFLen))
                {
                    // invalid protocol
                    LOGW("TrojanAuthServer: detected non trojan protocol, rejected");
                    goto failed;
                }
                // save time easily
                if (((unsigned char *) rawBuf(c->payload))[sizeof(sha224_hex_t)] != '\r' ||
                    ((unsigned char *) rawBuf(c->payload))[sizeof(sha224_hex_t) + 1] != '\n')
                {
                    LOGW("TrojanAuthServer: detected non trojan protocol, rejected");
                    goto failed;
                }

                hash_t kh = CALC_HASH_BYTES(rawBuf(c->payload), sizeof(sha224_hex_t));

                hmap_users_t_iter find_result = hmap_users_t_find(&(state->users), kh);
                if (find_result.ref == hmap_users_t_end(&(state->users)).ref)
                {
                    // user not in database
                    LOGW("TrojanAuthServer: a trojan-user rejected because not found in database");
                    goto failed;
                }
                trojan_user_t *tuser = (find_result.ref->second);
                if (! tuser->user.enable)
                {
                    // user disabled
                    LOGW("TrojanAuthServer: user \"%s\" rejected because not enabled", tuser->user.name);

                    goto failed;
                }
                LOGD("TrojanAuthServer: user \"%s\" accepted", tuser->user.name);
                cstate->authenticated = true;
                markAuthenticated(c->line);
                cstate->init_sent   = true;
                self->up->upStream(self->up, newInitContext(c->line));
                if (! isAlive(c->line))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }

                shiftr(c->payload, sizeof(sha224_hex_t) + kCRLFLen);
                self->up->upStream(self->up, c);
            }
            // gettimeofday(&tv2, NULL);
            // double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 + (double)(tv2.tv_sec -
            // tv1.tv_sec); LOGD("Auth: took %lf sec", time_spent);
            return;
        }

        goto failed;
    }
    else
    {
        if (c->init)
        {
            cstate = malloc(sizeof(trojan_auth_server_con_state_t));
            memset(cstate, 0, sizeof(trojan_auth_server_con_state_t));
            CSTATE_MUT(c) = cstate;
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = cstate->init_sent;
            bool auth      = cstate->authenticated;
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            if (init_sent)
            {
                if (auth)
                {
                    self->up->upStream(self->up, c);
                }
                else
                {
                    state->fallback->upStream(state->fallback, c);
                }
            }
            else
            {
                destroyContext(c);
            }
        }
    }

    return;
failed:;
    if (state->fallback != NULL)
    {
        goto fallback;
    }

// disconnect:;
    reuseContextBuffer(c);
    free(CSTATE(c));
    CSTATE_MUT(c)    = NULL;
    context_t *reply = newFinContextFrom(c);
    destroyContext(c);
    self->dw->downStream(self->dw, reply);
    return;
fallback:;
    if (! cstate->init_sent)
    {
        cstate->init_sent   = true;
        state->fallback->upStream(state->fallback, newInitContext(c->line));
        if (! isAlive(c->line))
        {
            reuseContextBuffer(c);
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
        htimer_t *t = htimer_add(c->line->loop, onFallbackTimer, state->fallback_delay, 1);
        hevent_set_userdata(t, newTimerData(self, c));
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);
}

static void parse(tunnel_t *t, cJSON *settings, size_t chain_index)
{
    trojan_auth_server_state_t *state = t->state;
    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->Settings (object field) was empty or invalid");
        exit(1);
    }
    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(settings, "users");
    if (! (cJSON_IsArray(users_array) && users_array->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->Settings->Users (array field) was empty or invalid");
        exit(1);
    }
    cJSON *element = NULL;

    unsigned int total_parsed = 0;
    unsigned int total_users  = 0;
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
            sha224((uint8_t *) tuser->user.uid, strlen(tuser->user.uid), &(tuser->hash_user[0]));

            for (size_t i = 0; i < sizeof(sha224_t); i++)
            {
                sprintf((char *) &(tuser->hash_hexed_user[i * 2]), "%02x", (tuser->hash_user[i]));
            }
            LOGD("TrojanAuthServer: user \"%s\" parsed, sha224: %.12s...", tuser->user.name, tuser->hash_hexed_user);

            tuser->komihash_of_hex = CALC_HASH_BYTES(tuser->hash_hexed_user, sizeof(sha224_hex_t));

            hmap_users_t_push(&(state->users), (hmap_users_t_value){tuser->komihash_of_hex, tuser});
        }

        total_users++;
    }
    LOGI("TrojanAuthServer: %zu users parsed (out of total %zu) and can connect", total_parsed, total_users);

    char *fallback_node = NULL;
    if (! getStringFromJsonObject(&fallback_node, settings, "fallback"))
    {
        LOGW("TrojanAuthServer: no fallback provided in json, standard trojan requires fallback");
    }
    else
    {

        getIntFromJsonObject(&(state->fallback_delay), settings, "fallback-intence-delay");
        if (state->fallback_delay < 0)
        {
            state->fallback_delay = 0;
        }


        hash_t  hash_next = CALC_HASH_BYTES(fallback_node, strlen(fallback_node));
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
    state->users    = hmap_users_t_with_capacity(kVecCap);
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TrojanAuthServer->settings (object field) : The object was empty or invalid");
        return NULL;
    }
    tunnel_t *t = newTunnel();
    t->state    = state;

    t->upStream   = &upStream;
    t->downStream = &downStream;
    parse(t, settings, instance_info->chain_index);

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiTrojanAuthServer(tunnel_t *self, const char *msg)
{

    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyTrojanAuthServer(tunnel_t *self)
{
    (void) self;
    return NULL;
}

tunnel_metadata_t getMetadataTrojanAuthServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
