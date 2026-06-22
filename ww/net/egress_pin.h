#pragma once

#include "wlibc.h"

void egressPinSet(const char *ifname, uint32_t idx_v4, uint32_t idx_v6);
void egressPinClear(void);
bool egressPinActive(void);
int  egressPinApply(int sockfd, int family, const char *explicit_ifname);
