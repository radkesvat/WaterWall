#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kTrojanClientAddressIpv4       = 1,
    kTrojanClientAddressDomain     = 3,
    kTrojanClientAddressIpv6       = 4,
    kTrojanClientAddressMaxEncoded = 259
};

typedef enum trojanclient_address_result_e
{
    kTrojanClientAddressInvalid  = -1,
    kTrojanClientAddressNeedMore = 0,
    kTrojanClientAddressComplete = 1
} trojanclient_address_result_t;

/* Owning, allocation-free value: exact wire identity, with no routing/DNS state.
 * Only length bytes are meaningful; padding and consumed are not identity. */
typedef struct trojanclient_address_s
{
    uint16_t port;
    uint16_t length;
    uint16_t consumed;
    uint8_t  kind;
    uint8_t  bytes[UINT8_MAX];
} trojanclient_address_t;

/* All outputs remain unchanged on incomplete/invalid input or failed encoding. */
trojanclient_address_result_t trojanclientAddressDecode(const uint8_t *wire, size_t length,
                                                        trojanclient_address_t *out);
/* Zero denotes an invalid value. */
size_t trojanclientAddressEncodedLength(const trojanclient_address_t *address);
bool trojanclientAddressEncode(const trojanclient_address_t *address, uint8_t *wire, size_t capacity, size_t *written);
