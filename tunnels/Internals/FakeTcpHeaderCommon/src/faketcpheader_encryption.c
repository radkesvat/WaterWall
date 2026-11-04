#include "FakeTcpHeaderCommon/faketcpheader_encryption.h"

#include "loggers/network_logger.h"

bool faketcpheaderEncryptionIsNode(const node_t *node)
{
    return node != NULL && node->type != NULL &&
           (stringCompare(node->type, "EncryptionClient") == 0 || stringCompare(node->type, "EncryptionServer") == 0);
}

bool faketcpheaderEncryptionCreate(faketcpheader_encryption_t *child, node_t *owner, faketcpheader_wire_side_t side)
{
    assert(child != NULL && owner != NULL && child->tunnel == NULL && child->settings == NULL);
    assert(side == kFakeTcpHeaderWireClient || side == kFakeTcpHeaderWireServer);
    const char *type       = side == kFakeTcpHeaderWireClient ? "EncryptionClient" : "EncryptionServer";
    node_t      descriptor = nodelibraryLoadByTypeName(type);
    if (descriptor.createHandle == NULL || descriptor.hash_type != calcHashBytes(type, stringLength(type)))
    {
        LOGF("%s: password requires the %s module, which is unavailable", owner->type, type);
        return false;
    }

    /* Registry templates retain their strings. The private child owns its copy. */
    descriptor.type       = stringDuplicate(type);
    const cJSON *password = cJSON_GetObjectItemCaseSensitive(owner->node_settings_json, "password");
    assert(cJSON_IsString(password) && password->valuestring[0] != '\0');
    child->settings = cJSON_CreateObject();
    cJSON_AddBoolToObject(child->settings, "packet-mode", true);
    cJSON_AddStringToObject(child->settings, "algorithm", "xchacha20-poly1305");
    cJSON_AddStringToObject(child->settings, "password", password->valuestring);
    if (! nodeConfigureChild(&child->node,
                             descriptor,
                             owner,
                             ".encryption",
                             side == kFakeTcpHeaderWireClient ? kNodeChildLinkOwnerNext : kNodeChildLinkNone,
                             child->settings))
    {
        return false;
    }
    child->tunnel = nodemanagerCreateTunnelInstance(&child->node);
    if (child->tunnel == NULL)
    {
        LOGF("%s: failed to construct the packet encryption helper", owner->type);
        return false;
    }
    child->node.instance = child->tunnel;
    return true;
}

void faketcpheaderEncryptionDestroy(faketcpheader_encryption_t *child)
{
    if (child->tunnel != NULL)
    {
        tunnelOwnedChildDestroy(child->tunnel);
    }
    if (child->settings != NULL)
    {
        cJSON *password = cJSON_GetObjectItemCaseSensitive(child->settings, "password");
        if (cJSON_IsString(password))
        {
            memorySecureZero(password->valuestring, stringLength(password->valuestring));
        }
        cJSON_Delete(child->settings);
    }
    memoryFree(child->node.name);
    memoryFree(child->node.type);
    memoryFree(child->node.next);
    memoryZero(child, sizeof(*child));
}
