#include "APIServer/structure.h"

const char *apiserverAuthorize(apiserver_tstate_t *ts, api_request_t *r, tunnel_t **target,
                               const node_api_operation_t **operation)
{
    api_client_t *client = ts->clients;
    for (; client; client = client->next)
        if (strcmp(client->name, r->client) == 0)
            break;
    uint8_t unknown[32] = {0};
    bool    equal       = wCryptoEqual(client ? client->token : unknown, r->token, 32);
    if (! client || ! equal)
    {
        r->close = true;
        return "unauthorized";
    }
    if (! nodeApiAdmissionIsOpen() || atomic_load(&ts->stopping))
        return "shutting_down";
    const char              *config = NULL;
    node_api_target_status_t found =
        nodemanagerResolveApiTarget(*r->config ? r->config : NULL, r->node, target, &config);
    if (found == kNodeApiTargetAmbiguous)
        return "ambiguous_target";
    if (found != kNodeApiTargetFound)
        return "target_not_found";
    /* Resolve global ambiguity before applying any permission filter. */
    api_permission_t *p = client->permissions;
    for (; p; p = p->next)
        if (p->target == *target && strcmp(p->config, config) == 0 && strcmp(p->node, r->node) == 0 &&
            strcmp(p->operation, r->operation) == 0)
            break;
    if (! p)
        return "forbidden";
    /* Preparation resolved this immutable descriptor before registry freeze.
     * Admission closes before targets or their registrations can be retired. */
    assert(p->descriptor != NULL && nodeApiFind(*target, p->operation) == p->descriptor);
    *operation = p->descriptor;
    if (strcmp((*operation)->request_content_type, r->content_type) != 0)
        return "unsupported_content_type";
    return NULL;
}
