#pragma once

/*
 * Public checksum API used to recompute IPv4 and transport checksums.
 */

#include "wplatform.h"

/**
 * @brief Select source or destination IPv4 address field.
 */
typedef enum ipv4_checksum_address_field_e
{
    kIpv4ChecksumAddressSource = 0,
    kIpv4ChecksumAddressDestination
} ipv4_checksum_address_field_e;

/**
 * @brief Recalculate IP and L4 checksum fields for an IPv4 packet buffer.
 *
 * @param buf Pointer to packet bytes starting at IPv4 header.
 * @param available_len Number of valid readable and writable bytes at @p buf.
 * @return true when a structurally valid IPv4 packet was processed, otherwise false without modifying the buffer.
 */
bool calcFullPacketChecksum(uint8_t *buf, size_t available_len);

/**
 * @brief Recalculate IPv4 header checksum only.
 *
 * @param buf Pointer to packet bytes starting at IPv4 header.
 * @param available_len Number of valid readable and writable bytes at @p buf.
 * @return true when a valid IPv4 header was updated, false without modifying the buffer for null/invalid/IPv6 input.
 */
bool calcIpv4HeaderChecksum(uint8_t *buf, size_t available_len);

/**
 * @brief Replace source or destination IPv4 address and incrementally update IPv4 and transport checksums.
 *
 * Preconditions:
 * - Valid input checksums are required when the caller expects immediately valid output checksums.
 * - Applying the algebraic delta to a known-dirty packet is allowed only when the caller already has an
 *   independent full recalculation pending and preserves that pending flag state.
 * - The helper never makes a stale checksum valid and never manages a line flag.
 *
 * @param buf Pointer to packet bytes starting at IPv4 header.
 * @param available_len Number of valid readable and writable bytes at @p buf.
 * @param field Selects source or destination address to replace.
 * @param new_address_network New IPv4 address in network byte order.
 * @return true on success (or if unchanged), false without modifying the buffer on failure.
 */
bool setIpv4AddressWithChecksumUpdate(uint8_t *buf, size_t available_len, ipv4_checksum_address_field_e field,
                                      uint32_t new_address_network);

/**
 * @brief Incrementally update TCP or UDP checksum after replacing one aligned 16-bit transport word.
 *
 * Preconditions:
 * - Valid input checksums are required when the caller expects immediately valid output checksums.
 * - Applying the algebraic delta to a known-dirty packet is allowed only when the caller already has an
 *   independent full recalculation pending and preserves that pending flag state.
 * - The helper never makes a stale checksum valid and never manages a line flag.
 * - @p old_word_network must represent the exact aligned 16-bit word currently covered by the checksum.
 * - Must not be used for fields appearing more than once in checksum input (such as the UDP length field)
 *   or for checksum fields themselves. Supported fields include TCP flags, TCP/UDP ports, sequence numbers,
 *   and payload words.
 *
 * @param buf Pointer to packet bytes starting at IPv4 header.
 * @param available_len Number of valid readable and writable bytes at @p buf.
 * @param old_word_network Old 16-bit word in network byte order.
 * @param new_word_network New 16-bit word in network byte order.
 * @return true on success (or if unchanged), false without modifying the buffer on failure.
 */
bool updateIpv4TransportChecksum16(uint8_t *buf, size_t available_len, uint16_t old_word_network,
                                   uint16_t new_word_network);

/**
 * Replace the address contributions to an IPv4 TCP/UDP checksum using RFC 1624.
 * effective_protocol is the underlying TCP/UDP protocol, independently of the
 * actual IP protocol byte. All four addresses are in network byte order.
 * Neither the actual addresses nor the IP/protocol checksum are changed.
 * Invalid checksum residuals are preserved; this never repairs or requests work.
 * Disabled UDP zero stays zero; enabled UDP arithmetic zero is stored as 0xffff.
 * Valid fragments without the checksum field succeed without writing transport
 * bytes; partial fields, invalid local geometry and malformed transport shapes
 * fail without mutation. Access is bounded by IPv4 total length.
 * Equal old/new address pairs provide a non-mutating preflight of the same range.
 */
bool updateIpv4TransportChecksumAddresses(uint8_t *buf, size_t available_len, uint8_t effective_protocol,
                                          uint32_t old_source_network, uint32_t old_destination_network,
                                          uint32_t new_source_network, uint32_t new_destination_network);

/**
 * @brief Compute a generic one's-complement checksum with an initial seed.
 *
 * @param data Input buffer.
 * @param len Number of bytes to include.
 * @param initial Initial running sum (pseudo-header seed, if any).
 * @return uint16_t Final checksum value in network byte order.
 */
uint16_t calcGenericChecksum(const uint8_t *data, uint16_t len, uint32_t initial);

/**
 * @brief Select and initialize the best checksum backend for this CPU.
 */
void checkSumInit(void);
