#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Shared explicit stream carrier. The caller serializes input and owns the
 * enclosing bytes. No automatic carrier detection or socket knowledge. */
typedef struct ww_quic_carrier
{
    uint8_t  header[4];
    uint8_t  header_used;
    uint32_t body_length;
    uint32_t body_used;
    uint8_t *body;
    void    *context;
    /* Allocation may refuse a storage budget; heap exhaustion remains fatal. */
    void *(*allocate)(void *context, size_t length);
    void (*deallocate)(void *context, void *pointer, size_t length);
} ww_quic_carrier_t;

typedef enum ww_quic_carrier_result
{
    WW_QUIC_CARRIER_MORE,
    WW_QUIC_CARRIER_PACKET,
    WW_QUIC_CARRIER_INVALID,
    WW_QUIC_CARRIER_REFUSED
} ww_quic_carrier_result_t;

/* Consumes at most one frame. PACKET borrows either input bytes or body until
 * release_packet; MORE retains only a partial header/body. Refusal and malformed
 * lengths are terminal. Input may contain arbitrarily fragmented/coalesced frames. */
ww_quic_carrier_result_t ww_quic_carrier_decode(ww_quic_carrier_t *carrier, const uint8_t *input, size_t length,
                                                size_t *consumed, const uint8_t **packet, size_t *packet_length);
void                     ww_quic_carrier_release_packet(ww_quic_carrier_t *carrier);
void                     ww_quic_carrier_destroy(ww_quic_carrier_t *carrier);
size_t                   ww_quic_carrier_retained(const ww_quic_carrier_t *carrier);
void                     ww_quic_carrier_header(uint8_t header[4], uint32_t length);
