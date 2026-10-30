#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kSocksAddressIpv4       = 1,
    kSocksAddressDomain     = 3,
    kSocksAddressIpv6       = 4,
    kSocksAddressMaxEncoded = 259
};

typedef enum socks_address_result_e
{
    kSocksAddressInvalid  = -1,
    kSocksAddressNeedMore = 0,
    kSocksAddressComplete = 1
} socks_address_result_t;

/* Owning, allocation-free value: exact wire identity, with no routing/DNS state.
 * Only length bytes are meaningful; bytes need not be NUL-terminated. Port is in
 * host order and may be zero; endpoint policy stays with the caller.
 * Padding and consumed are not identity. */
typedef struct socks_address_s
{
    uint16_t port;
    uint16_t length;
    uint16_t consumed;
    uint8_t  kind;
    uint8_t  bytes[UINT8_MAX];
} socks_address_t;

/* All outputs remain unchanged on incomplete/invalid input or failed encoding. */
socks_address_result_t socksAddressDecode(const uint8_t *wire, size_t length, socks_address_t *out);
/* Zero denotes an invalid value. */
size_t socksAddressEncodedLength(const socks_address_t *address);
bool   socksAddressEncode(const socks_address_t *address, uint8_t *wire, size_t capacity, size_t *written);
