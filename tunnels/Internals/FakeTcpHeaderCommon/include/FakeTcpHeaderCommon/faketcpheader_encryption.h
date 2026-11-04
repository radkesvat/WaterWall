#pragma once

#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

/* Optional private child; its descriptor is loaded through the node registry,
 * so unencrypted FakeTcpHeader does not require either Encryption module. */
typedef struct faketcpheader_encryption_s
{
    node_t    node;
    tunnel_t *tunnel;
    cJSON    *settings;
} faketcpheader_encryption_t;

bool faketcpheaderEncryptionCreate(faketcpheader_encryption_t *child, node_t *owner, faketcpheader_wire_side_t side);
void faketcpheaderEncryptionDestroy(faketcpheader_encryption_t *child);
bool faketcpheaderEncryptionIsNode(const node_t *node);
