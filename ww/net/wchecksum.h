#pragma once

/*
 * Public checksum API used to recompute IPv4 and transport checksums.
 */

#include "wplatform.h"

/**
 * @brief Recalculate IP and L4 checksum fields for an IPv4 packet buffer.
 *
 * @param buf Pointer to packet bytes starting at IPv4 header.
 * @param available_len Number of valid readable and writable bytes at @p buf.
 * @return true when a structurally valid IPv4 packet was processed, otherwise false without modifying the buffer.
 */
bool calcFullPacketChecksum(uint8_t *buf, size_t available_len);

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
