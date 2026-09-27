#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kTrojanServerAddressIpv4       = 1,
    kTrojanServerAddressDomain     = 3,
    kTrojanServerAddressIpv6       = 4,
    kTrojanServerAddressMaxEncoded = 259
};

typedef enum trojanserver_address_result_e
{
    kTrojanServerAddressInvalid  = -1,
    kTrojanServerAddressNeedMore = 0,
    kTrojanServerAddressComplete = 1
} trojanserver_address_result_t;

/* Owning, allocation-free value: exact wire identity, with no routing/DNS state.
 * Only length bytes are meaningful; padding and consumed are not identity. */
typedef struct trojanserver_address_s
{
    uint16_t port;
    uint16_t length;
    uint16_t consumed;
    uint8_t  kind;
    uint8_t  bytes[UINT8_MAX];
} trojanserver_address_t;

/* All outputs remain unchanged on incomplete/invalid input or failed encoding. */
trojanserver_address_result_t trojanserverAddressDecode(const uint8_t *wire, size_t length,
                                                        trojanserver_address_t *out);
/* Zero denotes an invalid value. */
size_t trojanserverAddressEncodedLength(const trojanserver_address_t *address);
bool trojanserverAddressEncode(const trojanserver_address_t *address, uint8_t *wire, size_t capacity, size_t *written);
