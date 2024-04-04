/*
 * Copyright (c) 2019 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#include "ipcalc.h"
#include "ipv6.h"

static void deaggregate_v4(const char *ip1s, const char *ip2s, unsigned flags);
static void deaggregate_v6(const char *ip1s, const char *ip2s, unsigned flags);

static char *trim(char *str)
{
	int len, i;
	char *out;

	len = strlen(str);
	for (i=len-1;i>=0;i--) {
		if (isspace(str[i]))
			str[i] = 0;
		else
			break;
	}

	out = str;
	for (i=0;i<len;i++) {
		if (isspace(str[i]))
			out++;
		else
			break;
	}

	return out;
}

void deaggregate(char *str, unsigned flags)
{
	char *d1Str = NULL, *d2Str = NULL;

	d1Str = strtok(str, "-");
	if (d1Str == NULL) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: bad deaggregation string: %s\n", str);
		exit(1);
	}
	d1Str = trim(d1Str);


	d2Str = strtok(NULL, "-");
	if (d2Str == NULL) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: bad deaggregation string: %s\n", str);
		exit(1);
	}
	d2Str = trim(d2Str);

	if (flags & FLAG_IPV6)
		deaggregate_v6(d1Str, d2Str, flags);
	else
		deaggregate_v4(d1Str, d2Str, flags);
}

static void print_ipv4_net(unsigned *jsonchain, uint32_t ip, unsigned prefix, unsigned flags)
{
	char namebuf[INET_ADDRSTRLEN + 1] = {0};
	struct in_addr s;

	s.s_addr = htonl(ip);

	if (inet_ntop(AF_INET, &s, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "inet_ntop failure at line %d\n",
			__LINE__);
		exit(1);
	}

	default_printf(jsonchain, "Network:\t", NULL, "%s/%u", namebuf, prefix);
}

void deaggregate_v4(const char *ip1s, const char *ip2s, unsigned flags)
{
	struct in_addr ip1, ip2;
	unsigned step;
	uint32_t base, end;
	unsigned jsonchain;

	if (inet_pton(AF_INET, ip1s, &ip1) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 address: %s\n",
				ip1s);
		exit(1);
	}

	if (inet_pton(AF_INET, ip2s, &ip2) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 address: %s\n",
				ip2s);
		exit(1);
	}

	base = ntohl(ip1.s_addr);
	end = ntohl(ip2.s_addr);

	if (base > end) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad range\n");
		exit(1);
	}

	output_start(&jsonchain);
	array_start(&jsonchain, "Deaggregated networks", "DEAGGREGATEDNETWORK");

	while (base <= end) {
		step = 0;
		while ((base | (1 << step)) != base) {
			if ((base | (UINT32_MAX >> (31-step))) > end)
				break;
			step++;
		}

		print_ipv4_net(&jsonchain, base, 32-step, flags);
		base += (1 << step);
	}

	array_stop(&jsonchain);
	output_stop(&jsonchain);

	return;
}

static void print_ipv6_net(unsigned *jsonchain, struct in6_addr *ip, unsigned prefix, unsigned flags)
{
	char namebuf[INET6_ADDRSTRLEN + 1] = {0};

	if (inet_ntop(AF_INET6, ip, namebuf, sizeof(namebuf)) == NULL) {
		fprintf(stderr, "inet_ntop failure at line %d\n",
			__LINE__);
		exit(1);
	}

	default_printf(jsonchain, "Network:\t", NULL, "%s/%u", namebuf, prefix);
}

static unsigned ipv6_base_ok(struct in6_addr *base, unsigned step)
{
	struct in6_addr b2;
	memcpy(&b2, base, sizeof(b2));

	ipv6_or1(&b2, step);

	return memcmp(base->s6_addr, &b2.s6_addr, 16);
}

void deaggregate_v6(const char *ip1s, const char *ip2s, unsigned flags)
{
	struct in6_addr ip1, ip2;
	unsigned step;
	struct in6_addr base, end;
	struct in6_addr tmp;
	unsigned jsonchain;

	if (inet_pton(AF_INET6, ip1s, &ip1) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n",
				ip1s);
		exit(1);
	}

	if (inet_pton(AF_INET6, ip2s, &ip2) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n",
				ip2s);
		exit(1);
	}

	memcpy(&base, &ip1, sizeof(base));
	memcpy(&end, &ip2, sizeof(end));

	if (ipv6_cmp(&base, &end) > 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 range\n");
		exit(1);
	}

	output_start(&jsonchain);
	array_start(&jsonchain, "Deaggregated networks", "DEAGGREGATEDNETWORK");


	while (ipv6_cmp(&base, &end) <= 0) {
		step = 0;
		while (ipv6_base_ok(&base, step)) {
			memcpy(&tmp, &base, sizeof(tmp));
			ipv6_orm(&tmp, step+1);
			if (ipv6_cmp(&tmp, &end) > 0)
				break;
			step++;
		}

		print_ipv6_net(&jsonchain, &base, 128-step, flags);
		memset(&tmp, 0, sizeof(tmp));
		ipv6_or1(&tmp, step);

		/* v6add */
		ipv6_add(&base, &tmp);
	}

	array_stop(&jsonchain);
	output_stop(&jsonchain);

	return;
}
