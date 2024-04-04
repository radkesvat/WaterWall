/*
 * Copyright (c) 2015 Red Hat, Inc. All rights reserved.
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
 *
 * Authors:
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "ipcalc.h"

/* draft-ietf-dnsop-rfc2317bis-00 replaces that legacy style
 */
#undef USE_RFC2317_STYLE

char *calc_reverse_dns4(struct in_addr ip, unsigned prefix, struct in_addr network, struct in_addr broadcast)
{
	char *str = NULL;
	int ret = -1;

	unsigned byte1 = (ntohl(ip.s_addr) >> 24) & 0xff;
	unsigned byte2 = (ntohl(ip.s_addr) >> 16) & 0xff;
	unsigned byte3 = (ntohl(ip.s_addr) >> 8) & 0xff;
	unsigned byte4 = (ntohl(ip.s_addr)) & 0xff;

#ifdef USE_RFC2317_STYLE
	if (prefix == 32) {
		ret = asprintf(&str, "%u.%u.%u.%u.in-addr.arpa.", byte4, byte3, byte2, byte1);
	} else if (prefix == 24) {
		ret = asprintf(&str, "%u.%u.%u.in-addr.arpa.", byte3, byte2, byte1);
	} else if (prefix == 16) {
		ret = asprintf(&str, "%u.%u.in-addr.arpa.", byte2, byte1);
	} else if (prefix == 8) {
		ret = asprintf(&str, "%u.in-addr.arpa.", byte1);
	} else if (prefix > 24) {
		ret = asprintf(&str, "%u/%u.%u.%u.%u.in-addr.arpa.", byte4, prefix, byte3, byte2, byte1);
	} else if (prefix > 16) {
		ret = asprintf(&str, "%u/%u.%u.%u.in-addr.arpa.", byte3, prefix, byte2, byte1);
	} else if (prefix > 8) {
		ret = asprintf(&str, "%u/%u.%u.in-addr.arpa.", byte2, prefix, byte1);
	}
#else
	if (prefix == 32) {
		ret = asprintf(&str, "%u.%u.%u.%u.in-addr.arpa.", byte4, byte3, byte2, byte1);
	} else if (prefix == 24) {
		ret = asprintf(&str, "%u.%u.%u.in-addr.arpa.", byte3, byte2, byte1);
	} else if (prefix == 16) {
		ret = asprintf(&str, "%u.%u.in-addr.arpa.", byte2, byte1);
	} else if (prefix == 8) {
		ret = asprintf(&str, "%u.in-addr.arpa.", byte1);
	} else if (prefix > 24) {
		unsigned min = (ntohl(network.s_addr)) & 0xff;
		unsigned max = (ntohl(broadcast.s_addr)) & 0xff;
		ret = asprintf(&str, "%u-%u.%u.%u.%u.in-addr.arpa.", min, max, byte3, byte2, byte1);
	} else if (prefix > 16) {
		unsigned min = (ntohl(network.s_addr) >> 8) & 0xff;
		unsigned max = (ntohl(broadcast.s_addr) >> 8) & 0xff;
		ret = asprintf(&str, "%u-%u.%u.%u.in-addr.arpa.", min, max, byte2, byte1);
	} else if (prefix > 8) {
		unsigned min = (ntohl(network.s_addr) >> 16) & 0xff;
		unsigned max = (ntohl(broadcast.s_addr) >> 16) & 0xff;
		ret = asprintf(&str, "%u-%u.%u.in-addr.arpa.", min, max, byte1);
	}
#endif

	if (ret == -1)
	    return NULL;
	return str;
}

static char hexchar(unsigned int val)
{
	if (val < 10)
		return '0' + val;
	if (val < 16)
		return 'a' + val - 10;
	abort();
}

char *calc_reverse_dns6(struct in6_addr *ip, unsigned prefix)
{
	unsigned i, j = 0;
	char str[256];
	unsigned max = prefix/8;

	if (prefix % 4 != 0)
		return NULL;

	if (prefix % 8 == 4) {
		str[j++] = hexchar(ip->s6_addr[(prefix+4)/8-1] >> 4);
		str[j++] = '.';
	}

	for (i=0;i<max;i++) {
		str[j++] = hexchar(ip->s6_addr[max-1-i] & 0xf);
		str[j++] = '.';

		str[j++] = hexchar(ip->s6_addr[max-1-i] >> 4);
		str[j++] = '.';

	}

	strcpy(&str[j], "ip6.arpa.");

	return strdup(str);
}
