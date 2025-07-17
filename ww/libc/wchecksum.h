#pragma once
#include "wplatform.h"

void calcFullPacketChecksum(uint8_t *buf);

// initial is seed for checksum calculation
uint16_t calcGenericChecksum(const uint8_t *data, size_t len, uint16_t initial);

void checkSumInit(void);
