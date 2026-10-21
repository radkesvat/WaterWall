#include "node_api.h"

typedef struct node_api_registration_s
{
    tunnel_t                       *instance;
    const node_api_operation_t     *operations;
    size_t                          count;
    struct node_api_registration_s *next;
} node_api_registration_t;

static node_api_registration_t *node_api_registrations;
static atomic_bool              node_api_admission;
static bool                     node_api_frozen;
static bool                     node_api_required;

void nodeApiRegistryInitialize(void)
{
    assert(node_api_registrations == NULL);
    node_api_frozen   = false;
    node_api_required = false;
    atomicStoreExplicit(&node_api_admission, false, memory_order_release);
}

void nodeApiRequireEnabled(void)
{
    assert(! node_api_frozen);
    node_api_required = true;
}

bool nodeApiIsRequired(void)
{
    return node_api_required;
}

bool nodeApiRegister(tunnel_t *instance, const node_api_operation_t *operations, size_t count)
{
    assert(instance != NULL && operations != NULL && count > 0);
    assert(! node_api_frozen);
    if (nodeApiHasRegistration(instance))
        return false;
    for (size_t i = 0; i < count; ++i)
    {
        const node_api_operation_t *operation = &operations[i];
        if (operation->name == NULL || operation->name[0] == '\0' || strlen(operation->name) > 64 ||
            operation->handler == NULL || operation->request_content_type == NULL ||
            operation->request_content_type[0] == '\0' || strlen(operation->request_content_type) > 128 ||
            operation->response_content_type == NULL || operation->response_content_type[0] == '\0' ||
            strlen(operation->response_content_type) > 128 ||
            (operation->response_encoding != kNodeApiEncodingUtf8 &&
             operation->response_encoding != kNodeApiEncodingBase64) ||
            (operation->execution != kNodeApiCallingWorker && operation->execution != kNodeApiSpecifiedWorker) ||
            (operation->execution == kNodeApiSpecifiedWorker && ! workerWIDIsRegistered(operation->wid)))
            return false;
        for (size_t j = 0; j < i; ++j)
            if (strcmp(operations[j].name, operation->name) == 0)
                return false;
    }
    node_api_registration_t *registration = memoryAllocate(sizeof(*registration));
    *registration                         = (node_api_registration_t) {
                                .instance = instance, .operations = operations, .count = count, .next = node_api_registrations};
    node_api_registrations = registration;
    return true;
}

void nodeApiUnregister(tunnel_t *instance)
{
    node_api_registration_t **entry = &node_api_registrations;
    while (*entry != NULL)
    {
        if ((*entry)->instance == instance)
        {
            node_api_registration_t *removed = *entry;
            *entry                           = removed->next;
            memoryFree(removed);
            return;
        }
        entry = &(*entry)->next;
    }
}

const node_api_operation_t *nodeApiFind(const tunnel_t *instance, const char *operation)
{
    assert(instance != NULL && operation != NULL);
    for (const node_api_registration_t *entry = node_api_registrations; entry != NULL; entry = entry->next)
        if (entry->instance == instance)
            for (size_t i = 0; i < entry->count; ++i)
                if (strcmp(entry->operations[i].name, operation) == 0)
                    return &entry->operations[i];
    return NULL;
}

bool nodeApiHasRegistration(const tunnel_t *instance)
{
    for (const node_api_registration_t *entry = node_api_registrations; entry != NULL; entry = entry->next)
        if (entry->instance == instance)
            return true;
    return false;
}

void nodeApiFreeze(void)
{
    node_api_frozen = true;
    atomicStoreExplicit(&node_api_admission, true, memory_order_release);
}

bool nodeApiAdmissionIsOpen(void)
{
    return atomicLoadExplicit(&node_api_admission, memory_order_acquire);
}

void nodeApiCloseAdmission(void)
{
    atomicStoreExplicit(&node_api_admission, false, memory_order_release);
}

void nodeApiRegistryDestroy(void)
{
    nodeApiCloseAdmission();
    assert(node_api_registrations == NULL);
    node_api_frozen   = false;
    node_api_required = false;
}

uint64_t nodeApiNowMs(void)
{
    return getHRTimeUs() / 1000U;
}
