/*
 * Copyright (c) 2019 Nikos Mavrogiannopoulos
 * Copyright 1991-1997, 1999-2014 Free Software Foundation, Inc.
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
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

/* Adds the two IP addresses and places the output in ap. This is based
 * on Niels Moeller's mini-gmp. */
void ipv6_add(struct in6_addr *ap, const struct in6_addr *bp)
{
	int i;
	uint8_t cy;

	for (i = 15, cy = 0; i >= 0; i--) {
		uint8_t a, b, r;
		a = ap->s6_addr[i];
		b = bp->s6_addr[i];
		r = a + cy;
		cy = (r < cy);
		r += b;
		cy += (r < b);
		ap->s6_addr[i] = r;
	}
	return;
}

/* Sets the "bit" of the IPv6 address to one */
void ipv6_or1(struct in6_addr *a, unsigned bit)
{
	unsigned byte = bit / 8;
	unsigned shift = bit % 8;

	assert(bit < 128);

	a->s6_addr[15 - byte] |= 1 << shift;
}

/* Sets all bits below "bits" to one */
void ipv6_orm(struct in6_addr *a, unsigned bits)
{
	int i;
	unsigned bytes = bits / 8;

	assert(bits < 128);

	for (i = 0; i < bytes; i++)
		a->s6_addr[15 - i] |= 0xff;

	for (i = bytes * 8; i < bits; i++)
		ipv6_or1(a, i);
}

/* Returns 1 if IP a is greater than IP b, 0 if equal, -1 if less */
int ipv6_cmp(struct in6_addr *a, struct in6_addr *b)
{
	unsigned i;
	for (i = 0; i < 16; i++) {
		if (a->s6_addr[i] != b->s6_addr[i])
			return a->s6_addr[i] > b->s6_addr[i] ? 1 : -1;
	}
	return 0;
}
