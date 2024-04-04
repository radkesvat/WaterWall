/*
 * Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
 * Authors:
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#ifndef _IPCALC_H
#define _IPCALC_H

#include <stdarg.h> /* for va_list */

#if defined(USE_GEOIP)
  void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char  **coord);
  int geo_setup(void);
# ifndef USE_RUNTIME_LINKING
#   define geo_setup() 0
# endif
#elif defined(USE_MAXMIND)
  void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char  **coord);
  int geo_setup(void);
# ifndef USE_RUNTIME_LINKING
#   define geo_setup() 0
# endif
#else
# define geo_ipv4_lookup(x,y,z,w,a)
# define geo_ipv6_lookup(x,y,z,w,a)
# define geo_setup() -1
#endif

int __attribute__((__format__(printf, 2, 3))) safe_asprintf(char **strp, const char *fmt, ...);
char __attribute__((warn_unused_result)) *safe_strdup(const char *str);
int safe_atoi(const char *s, int *ret_i);

char *calc_reverse_dns4(struct in_addr ip, unsigned prefix, struct in_addr net, struct in_addr bcast);
char *calc_reverse_dns6(struct in6_addr *ip, unsigned prefix);

uint32_t prefix2mask(int prefix);
int ipv6_prefix_to_mask(unsigned prefix, struct in6_addr *mask);

struct in_addr calc_network(struct in_addr addr, int prefix);

char *ipv4_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix);
char *ipv6_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix);

typedef struct ip_info_st {
	char *ip;
	char *expanded_ip;
	char *expanded_network;
	char *reverse_dns;

	char *network;
	char *broadcast;	/* ipv4 only */
	char *netmask;
	char *hostname;
	char *geoip_country;
	char *geoip_ccode;
	char *geoip_city;
	char *geoip_coord;
	char hosts[64];		/* number of hosts in text */
	unsigned prefix;

	char *hostmin;
	char *hostmax;
	const char *type;
	const char *class;
} ip_info_st;

enum app_t {
	APP_VERSION=1,
	APP_CHECK_ADDRESS=1<<1,
	APP_SHOW_INFO=1<<2,
	APP_SPLIT=1<<3,
	APP_DEAGGREGATE=1<<4
};

#define FLAG_IPV6 (1<<1)
#define FLAG_IPV4 (1<<2)
#define FLAG_SHOW_MODERN_INFO (1<<3)
#define FLAG_RESOLVE_IP (1<<4)
#define FLAG_RESOLVE_HOST (1<<5)
#define FLAG_SHOW_BROADCAST (1<<6)
#define FLAG_SHOW_NETMASK (1<<7)
#define FLAG_SHOW_NETWORK (1<<8)
#define FLAG_SHOW_PREFIX (1<<9)
#define FLAG_SHOW_MINADDR (1<<10)
#define FLAG_SHOW_MAXADDR (1<<11)
#define FLAG_SHOW_ADDRESSES (1<<12)
#define FLAG_SHOW_ADDRSPACE (1<<13)
#define FLAG_GET_GEOIP (1<<14)
#define FLAG_SHOW_GEOIP ((1<<15)|FLAG_GET_GEOIP)
#define FLAG_SHOW_ALL_INFO (1<<16)
#define FLAG_SHOW_REVERSE (1<<17)
#define FLAG_ASSUME_CLASS_PREFIX (1<<18)
#define FLAG_NO_DECORATE (1<<20)
#define FLAG_SHOW_ADDRESS (1<<21)
#define FLAG_JSON (1<<22)
#define FLAG_RANDOM (1<<23)

/* Flags that are modifying an existing option */
#define FLAGS_TO_IGNORE (FLAG_IPV6|FLAG_IPV4|FLAG_GET_GEOIP|FLAG_NO_DECORATE|FLAG_JSON|FLAG_ASSUME_CLASS_PREFIX|(1<<16)|FLAG_RANDOM)
#define FLAGS_TO_IGNORE_MASK (~FLAGS_TO_IGNORE)

#define ENV_INFO_FLAGS (FLAG_SHOW_NETMASK|FLAG_SHOW_BROADCAST|FLAG_RESOLVE_IP|FLAG_RESOLVE_HOST|FLAG_SHOW_ADDRESS|FLAG_SHOW_REVERSE|FLAG_SHOW_GEOIP|FLAG_SHOW_ADDRSPACE|FLAG_SHOW_ADDRESSES|FLAG_SHOW_MAXADDR|FLAG_SHOW_MINADDR|FLAG_SHOW_PREFIX|FLAG_SHOW_NETWORK)
#define ENV_INFO_MASK (~ENV_INFO_FLAGS)

void show_split_networks_v4(unsigned split_prefix, const struct ip_info_st *info, unsigned flags);
void show_split_networks_v6(unsigned split_prefix, const struct ip_info_st *info, unsigned flags);

void deaggregate(char *str, unsigned flags);

#define KBLUE  "\x1B[34m"
#define KMAG   "\x1B[35m"
#define KRESET "\033[0m"

#define JSON_FIRST 0
#define JSON_NEXT  1
#define JSON_ARRAY_FIRST 2
#define JSON_ARRAY_NEXT  3

void
__attribute__ ((format(printf, 3, 4)))
color_printf(const char *color, const char *title, const char *fmt, ...);
void
__attribute__ ((format(printf, 3, 4)))
json_printf(unsigned * const jsonfirst, const char *jsontitle, const char *fmt, ...);
void va_color_printf(const char *color, const char *title, const char *fmt, va_list varglist);
void va_json_printf(unsigned  * const jsonfirst, const char *jsontitle, const char *fmt, va_list varglist);

void
__attribute__ ((format(printf, 4, 5)))
default_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...);
void
__attribute__ ((format(printf, 4, 5)))
dist_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...);

void array_start(unsigned * const jsonfirst, const char *head, const char *json_head);
void array_stop(unsigned * const jsonfirst);
void output_start(unsigned * const jsonfirst);
void output_stop(unsigned * const jsonfirst);

extern int beSilent;

#endif
