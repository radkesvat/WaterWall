/*
 * Copyright (c) 2003-2016  Simon Ekstrand
 * Copyright (c) 2010-2016  Joachim Nilsson
 * Copyright (c) 2016 Nikos Mavrogiannopoulos
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "ipv6.h"
#include "ipcalc.h"

static const char *numtoquad(uint32_t num)
{
	static char quad[64];

	num = htonl(num);
	return inet_ntop(AF_INET, &num, quad, sizeof(quad));
}

void show_split_networks_v4(unsigned split_prefix, const struct ip_info_st *info, unsigned flags)
{
	char buf[64];
	uint32_t diff, start, end;
	size_t maxlen = 0;
	unsigned count;
	uint32_t splitmask = ntohl(prefix2mask(split_prefix));
	uint32_t nmask = ntohl(prefix2mask(info->prefix));
	struct in_addr net, broadcast;
	unsigned jsonchain = JSON_FIRST;

	if (splitmask < nmask) {
		if (!beSilent)
			fprintf(stderr, "Cannot subnet to /%d with this base network, use a prefix > /%d\n",
				split_prefix, info->prefix);
		exit(1);
	}

	output_start(&jsonchain);
	array_start(&jsonchain, "Split networks", "SPLITNETWORK");

	if (inet_pton(AF_INET, info->network, &net) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 address: %s\n", info->network);
		exit(1);
	}
	net.s_addr = ntohl(net.s_addr);

	if (inet_pton(AF_INET, info->broadcast, &broadcast) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad broadcast address: %s\n", info->broadcast);
		exit(1);
	}
	broadcast.s_addr = ntohl(broadcast.s_addr);

	diff  = 0xffffffff - splitmask + 1;
	start = net.s_addr;
	end   = net.s_addr + diff - 1;

	/* broadcast here is used to get maximum hosts in network. Set it to start + 1 for /31. */
	if (info->prefix == 31)
		broadcast.s_addr = start + 1;

	/* Figure out max width of a network string. */
	while (1) {
		size_t len;

		len = snprintf(buf, sizeof(buf), "%s", numtoquad(start));
		if (len > maxlen)
			maxlen = len;

		start += diff;
		if (end == 0xffffffff || end >= broadcast.s_addr)
			break;
		end += diff;
	}

	start = net.s_addr;
	end = net.s_addr + diff - 1;
	count = 0;
	while (1) {
		if (!(flags & FLAG_NO_DECORATE) || (flags & FLAG_JSON)) {
			default_printf(&jsonchain, "Network:\t", NULL, "%s/%u", numtoquad(start), split_prefix);
		} else {
			printf("%s/%u\n", numtoquad(start), split_prefix);
		}

		count++;
		start += diff;
		if (end == 0xffffffff || end >= broadcast.s_addr)
			break;
		end += diff;
	}

	array_stop(&jsonchain);

	if ((!(flags & FLAG_NO_DECORATE)) || (flags & FLAG_JSON)) {
		dist_printf(&jsonchain, "\nTotal:  \t", "NETS", "%u", count);
		dist_printf(&jsonchain, "Hosts/Net:\t", "ADDRESSES", "%s", ipv4_prefix_to_hosts(buf, sizeof(buf), split_prefix));
	}

	output_stop(&jsonchain);
}

static const char *ipv6tostr(struct in6_addr *ip)
{
	static char str[64];

	return inet_ntop(AF_INET6, ip, str, sizeof(str));
}

void show_split_networks_v6(unsigned split_prefix, const struct ip_info_st *info, unsigned flags)
{
	int i, j, k;
	unsigned count;
	struct in6_addr splitmask, net, netmask, sdiff, ediff, start, end, tmpaddr, netlast;
	char buf[32];
	unsigned jsonchain = JSON_FIRST;

	if (inet_pton(AF_INET6, info->network, &net) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n", info->network);
		exit(1);
	}

	if (inet_pton(AF_INET6, info->hostmax, &netlast) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n", info->hostmax);
		exit(1);
	}

	if (inet_pton(AF_INET6, info->netmask, &netmask) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 mask: %s\n", info->netmask);
		exit(1);
	}

	if (ipv6_prefix_to_mask(split_prefix, &splitmask) < 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: IPv6 prefix: %d\n", split_prefix);
		exit(1);
	}

	i = 0;
	j = 0;
	do {
		if (splitmask.s6_addr[i] > netmask.s6_addr[i])
			j = 1;
		if (netmask.s6_addr[i] > splitmask.s6_addr[i])
			j = 2;
		i++;
	} while (i < 16 && !j);

	if (j == 2) {
		if (!beSilent)
			fprintf(stderr, "Cannot subnet to /%d with this base network, use a prefix > /%d\n",
				split_prefix, info->prefix);
		exit(1);
	}

	memset(&sdiff, 0, sizeof(sdiff));
	memset(&ediff, 0, sizeof(ediff));

	for (i = 0; i < 16; i++) {
		sdiff.s6_addr[i] = 0xff - splitmask.s6_addr[i];
		end.s6_addr[i] = net.s6_addr[i] + sdiff.s6_addr[i];
	}

	memcpy(&start, &net, sizeof(net));
	memcpy(&ediff, &sdiff, sizeof(sdiff));

	memset(&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.s6_addr[15] = 1;
	ipv6_add(&sdiff, &tmpaddr);

	output_start(&jsonchain);

	array_start(&jsonchain, "Split networks", "SPLITNETWORK");

	i = count = 0;
	while (!i) {
		if (!(flags & FLAG_NO_DECORATE) || (flags & FLAG_JSON)) {
			default_printf(&jsonchain, "Network:\t", NULL, "%s/%u", ipv6tostr(&start), split_prefix);
		} else {
			printf("%s/%u\n", ipv6tostr(&start), split_prefix);
		}

		ipv6_add(&start, &sdiff);

		j = 0;
		for (k = 0; k < 16; k+=2)
			if (end.s6_addr[k] != 0xff && end.s6_addr[k+1] != 0xff)
				j = 1;
		if (!j)
			i = 1;

		j = 0;
		k = 0;
		do {
			if (end.s6_addr[k] > netlast.s6_addr[k])
				j = 1;
			if (netlast.s6_addr[k] > end.s6_addr[k])
				j = 2;
			k++;
		} while (k < 16 && !j);

		if (!j || j == 1)
			i = 1;

		memset(&end, 0, sizeof(end));

		ipv6_add(&end, &start);
		ipv6_add(&end, &ediff);
		count++;
	}

	array_stop(&jsonchain);

	if ((!(flags & FLAG_NO_DECORATE)) || (flags & FLAG_JSON)) {
		dist_printf(&jsonchain, "\nTotal:  \t", "NETS", "%u", count);
		dist_printf(&jsonchain, "Hosts/Net:\t", "ADDRESSES", "%s", ipv6_prefix_to_hosts(buf, sizeof(buf), split_prefix));
	}

	output_stop(&jsonchain);

}

