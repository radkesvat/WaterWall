/*
 * Copyright (c) 2019 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef IPV6_H
#define IPV6_H

#include <netinet/in.h>
#include <arpa/inet.h>

void ipv6_add(struct in6_addr *a, const struct in6_addr *b);
void ipv6_or1(struct in6_addr *a, unsigned bit);
void ipv6_orm(struct in6_addr *a, unsigned bit);
int ipv6_cmp(struct in6_addr *a, struct in6_addr *b);

#endif
