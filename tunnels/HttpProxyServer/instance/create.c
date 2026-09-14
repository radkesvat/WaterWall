#include "UserController/interface.h"
#include "loggers/network_logger.h"
#include "structure.h"

static bool integer(const cJSON *json, const char *name, uint32_t def, uint32_t low, uint32_t high, uint32_t *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(json, name);
    *out           = def;
    if (! v)
        return true;
    if (! cJSON_IsNumber(v) || ! (v->valuedouble >= low && v->valuedouble <= high) ||
        v->valuedouble != (double) (uint32_t) v->valuedouble)
        return false;
    *out = (uint32_t) v->valuedouble;
    return true;
}

static bool credential(const cJSON *value, bool username)
{
    if (! cJSON_IsString(value))
        return false;
    size_t n = stringLength(value->valuestring);
    if (! n || n > 255)
        return false;
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char c = (unsigned char) value->valuestring[i];
        if (c < 32 || c == 127 || (username && c == ':'))
            return false;
    }
    return true;
}

static bool localUsers(hps_tstate_t *ts, const cJSON *users)
{
    if (! cJSON_IsArray(users) || ! users->child)
        return false;
    size_t       count = 0;
    const cJSON *entry;
    cJSON_ArrayForEach(entry, users)
    {
        if (count == SIZE_MAX / sizeof(*ts->users))
            return false;
        ++count;
    }
    ts->users = memoryAllocateZero(count * sizeof(*ts->users));
    if (! ts->users)
        return false;
    ts->user_count = count; /* Destruction also clears partially populated storage. */
    size_t index   = 0;
    cJSON_ArrayForEach(entry, users)
    {
        if (! cJSON_IsObject(entry))
            return false;
        unsigned     seen = 0;
        const cJSON *field;
        cJSON_ArrayForEach(field, entry)
        {
            unsigned bit = ! stringCompare(field->string, "username")   ? 1
                           : ! stringCompare(field->string, "password") ? 2
                                                                        : 0;
            if (! bit || (seen & bit) || ! credential(field, bit == 1))
                return false;
            seen |= bit;
        }
        if (seen != 3)
            return false;
        hps_local_user_t *user = &ts->users[index];
        stringCopy(user->username, cJSON_GetObjectItemCaseSensitive(entry, "username")->valuestring);
        stringCopy(user->password, cJSON_GetObjectItemCaseSensitive(entry, "password")->valuestring);
        for (size_t i = 0; i < index; ++i)
            if (! stringCompare(user->username, ts->users[i].username) &&
                ! stringCompare(user->password, ts->users[i].password))
                return false;
        ++index;
    }
    return true;
}

static bool parse(hps_tstate_t *ts, node_t *node)
{
    const cJSON *json = node->node_settings_json;
    if (! cJSON_IsObject(json) || ! nodeHasNext(node))
        return false;
    const char  *keys[] = {"no-auth",
                           "users",
                           "auth-client-node-name",
                           "sweep-interval-ms",
                           "max-header-bytes",
                           "max-pending-bytes",
                           "header-timeout-ms",
                           "connect-timeout-ms",
                           "idle-timeout-ms",
                           "verbose"};
    const cJSON *item;
    cJSON_ArrayForEach(item, json)
    {
        bool known = false;
        for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
            known |= ! stringCompare(item->string, keys[i]);
        if (! known)
            return false;
        for (const cJSON *other = item->next; other; other = other->next)
            if (! stringCompare(item->string, other->string))
                return false;
    }
    const cJSON *noauth  = cJSON_GetObjectItemCaseSensitive(json, "no-auth");
    const cJSON *verbose = cJSON_GetObjectItemCaseSensitive(json, "verbose");
    const cJSON *auth    = cJSON_GetObjectItemCaseSensitive(json, "auth-client-node-name");
    const cJSON *users   = cJSON_GetObjectItemCaseSensitive(json, "users");
    if ((noauth && ! cJSON_IsBool(noauth)) || (verbose && ! cJSON_IsBool(verbose)))
        return false;
    ts->verbose = cJSON_IsTrue(verbose);
    if ((unsigned) cJSON_IsTrue(noauth) + (auth != NULL) + (users != NULL) != 1)
        return false;
    ts->auth_mode = users ? kHpsAuthLocal : auth ? kHpsAuthTracked : kHpsAuthNone;
    if (auth)
    {
        if (! cJSON_IsString(auth) || ! auth->valuestring[0])
            return false;
        ts->auth_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth->valuestring);
        if (! ts->auth_node || stringCompare(ts->auth_node->type, "AuthenticationClient"))
            return false;
    }
    else if (users && ! localUsers(ts, users))
        return false;
    uint32_t sweep;
    return integer(json, "max-header-bytes", 32768, 1024, 65536, &ts->max_header) &&
           integer(json, "max-pending-bytes", 262144, 65536, 1048576, &ts->max_pending) &&
           ts->max_pending >= ts->max_header &&
           integer(json, "header-timeout-ms", 15000, 1, INT32_MAX, &ts->header_timeout) &&
           integer(json, "connect-timeout-ms", 30000, 1, INT32_MAX, &ts->connect_timeout) &&
           integer(json, "idle-timeout-ms", 300000, 1, INT32_MAX, &ts->idle_timeout) &&
           integer(json, "sweep-interval-ms", 1000, 1, INT32_MAX, &sweep);
}

tunnel_t *httpproxyserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(hps_tstate_t), sizeof(hps_lstate_t));
    if (! t)
        return NULL;
    hps_tstate_t *ts   = tunnelGetState(t);
    t->fnInitU         = httpproxyserverTunnelUpStreamInit;
    t->fnFinU          = httpproxyserverTunnelUpStreamFinish;
    t->fnPayloadU      = httpproxyserverTunnelUpStreamPayload;
    t->fnPauseU        = httpproxyserverTunnelUpStreamPause;
    t->fnResumeU       = httpproxyserverTunnelUpStreamResume;
    t->fnEstD          = httpproxyserverTunnelDownStreamEst;
    t->fnFinD          = httpproxyserverTunnelDownStreamFinish;
    t->fnPayloadD      = httpproxyserverTunnelDownStreamPayload;
    t->fnPauseD        = httpproxyserverTunnelDownStreamPause;
    t->fnResumeD       = httpproxyserverTunnelDownStreamResume;
    t->onChain         = httpproxyserverTunnelOnChain;
    t->onPrepare       = httpproxyserverTunnelOnPrepair;
    t->onWorkerQuiesce = httpproxyserverTunnelOnWorkerQuiesce;
    t->onWorkerStop    = httpproxyserverTunnelOnWorkerStop;
    t->onDestroy       = httpproxyserverTunnelDestroy;
    if (! parse(ts, node))
    {
        LOGF("HttpProxyServer: invalid settings, authentication selection, or missing next node");
        goto fail;
    }
    ts->worker_count = getWorkersCount();
    ts->workers      = memoryAllocateZero(sizeof(*ts->workers) * ts->worker_count);
    if (! ts->workers)
        goto fail;
    if (ts->auth_mode == kHpsAuthTracked)
    {
        if (! nodeConfigureChild(&ts->controller_node,
                                 nodeUserControllerGet(),
                                 node,
                                 ".user-controller",
                                 kNodeChildLinkOwnerNext,
                                 node->node_settings_json))
            goto fail;
        ts->controller = nodemanagerCreateTunnelInstance(&ts->controller_node);
        if (! ts->controller)
            goto fail;
        ts->controller_node.instance = ts->controller;
    }
    return t;
fail:
    httpproxyserverTunnelDestroy(t, NULL);
    return NULL;
}
