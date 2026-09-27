#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    kSocks5AddressIpv4       = 1,
    kSocks5AddressDomain     = 3,
    kSocks5AddressIpv6       = 4,
    kSocks5AddressMaxEncoded = 259
};

typedef enum socks5_address_result_e
{
    kSocks5AddressInvalid  = -1,
    kSocks5AddressNeedMore = 0,
    kSocks5AddressComplete = 1
} socks5_address_result_t;

/* Owning, allocation-free value: exact wire identity, with no routing/DNS state.
 * Only length bytes are meaningful; padding and consumed are not identity. */
typedef struct socks5_address_s
{
    uint8_t  kind;
    size_t   length;
    uint8_t  bytes[UINT8_MAX];
    uint16_t port;
    size_t   consumed;
} socks5_address_t;

/* All outputs remain unchanged on incomplete/invalid input or failed encoding. */
socks5_address_result_t socks5AddressDecode(const uint8_t *wire, size_t length, socks5_address_t *out);
/* Zero denotes an invalid value. */
size_t socks5AddressEncodedLength(const socks5_address_t *address);
bool   socks5AddressEncode(const socks5_address_t *address, uint8_t *wire, size_t capacity, size_t *written);
