/*
 * Copyright (c) 1997-2015 Red Hat, Inc. All rights reserved.
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
 *   Erik Troan <ewt@redhat.com>
 *   Preston Brown <pbrown@redhat.com>
 *   David Cantrell <dcantrell@redhat.com>
 */

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>		/* open */
#include <fcntl.h>		/* open */
#include <unistd.h>		/* read */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>		/* clock_gettime */
#include "ipcalc.h"

int beSilent = 0;
static unsigned colors = 0;
static unsigned flags = 0;

/*!
  \file ipcalc.c
  \brief provides utilities for manipulating IP addresses.

  ipcalc provides utilities and a front-end command line interface for
  manipulating IP addresses, and calculating various aspects of an ip
  address/netmask/network address/prefix/etc.

  Functionality can be accessed from other languages from the library
  interface, documented here.  To use ipcalc from the shell, read the
  ipcalc(1) manual page.

  When passing parameters to the various functions, take note of whether they
  take host byte order or network byte order.  Most take host byte order, and
  return host byte order, but there are some exceptions.
*/

/*!
  \fn uint32_t prefix2mask(int bits)
  \brief creates a netmask from a specified number of bits

  This function converts a prefix length to a netmask.  As CIDR (classless
  internet domain internet domain routing) has taken off, more an more IP
  addresses are being specified in the format address/prefix
  (i.e. 192.168.2.3/24, with a corresponding netmask 255.255.255.0).  If you
  need to see what netmask corresponds to the prefix part of the address, this
  is the function.  See also \ref mask2prefix.

  \param prefix is the number of bits to create a mask for.
  \return a network mask, in network byte order.
*/
uint32_t prefix2mask(int prefix)
{
	struct in_addr mask;
	memset(&mask, 0, sizeof(mask));
	if (prefix) {
		return htonl(~((1 << (32 - prefix)) - 1));
	} else {
		return htonl(0);
	}
}

/*!
  \fn struct in_addr calc_broadcast(struct in_addr addr, int prefix)

  \brief calculate broadcast address given an IP address and a prefix length.

  \param addr an IP address in network byte order.
  \param prefix a prefix length.

  \return the calculated broadcast address for the network, in network byte
  order.
*/
static struct in_addr calc_broadcast(struct in_addr addr, int prefix)
{
	struct in_addr mask;
	struct in_addr broadcast;

	mask.s_addr = prefix2mask(prefix);

	memset(&broadcast, 0, sizeof(broadcast));

	/* Follow RFC3021 and set the limited broadcast address on /31 */
	if (prefix == 31)
		broadcast.s_addr = htonl(0xFFFFFFFF);
	else
		broadcast.s_addr = (addr.s_addr & mask.s_addr) | ~mask.s_addr;

	return broadcast;
}

/*!
  \fn struct in_addr calc_network(struct in_addr addr, int prefix)
  \brief calculates the network address for a specified address and prefix.

  \param addr an IP address, in network byte order
  \param prefix the network prefix
  \return the base address of the network that addr is associated with, in
  network byte order.
*/
struct in_addr calc_network(struct in_addr addr, int prefix)
{
	struct in_addr mask;
	struct in_addr network;

	mask.s_addr = prefix2mask(prefix);

	memset(&network, 0, sizeof(network));
	network.s_addr = addr.s_addr & mask.s_addr;
	return network;
}

/*!
  \fn const char *get_hostname(int family, void *addr)
  \brief returns the hostname associated with the specified IP address

  \param family the address family, either AF_INET or AF_INET6.
  \param addr an IP address to find a hostname for, in network byte order,
  should either be a pointer to a struct in_addr or a struct in6_addr.

  \return a hostname, or NULL if one cannot be determined.  Hostname is stored
  in an allocated buffer.
*/
static char *get_hostname(int family, void *addr)
{
	static char hostname[NI_MAXHOST];
	int ret = -1;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;

	if (family == AF_INET) {
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		memcpy(&addr4.sin_addr, addr, sizeof(struct in_addr));
		ret = getnameinfo((struct sockaddr*)&addr4, sizeof(addr4), hostname, sizeof(hostname), NULL, 0, 0);
	} else if (family == AF_INET6) {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr, addr, sizeof(struct in6_addr));
		ret = getnameinfo((struct sockaddr*)&addr6, sizeof(addr6), hostname, sizeof(hostname), NULL, 0, 0);
	}

	if (ret != 0)
		return NULL;

	return safe_strdup(hostname);
}

/*!
  \fn const char *get_ip_address(int family, void *addr)
  \brief returns the IP address associated with the specified hostname

  \param family the requested address family or AF_UNSPEC for any
  \param host a hostname

  \return an IP address, or NULL if one cannot be determined.  The IP is stored
  in an allocated buffer.
*/
static char *get_ip_address(int family, const char *host)
{
	struct addrinfo *res, *rp;
	struct addrinfo hints;
	int err;
	static char ipname[64];
	void *addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;

	err = getaddrinfo(host, NULL, &hints, &res);
	if (err != 0)
		return NULL;

	for (rp=res;rp!=NULL;rp=rp->ai_next) {
		if (rp->ai_family == AF_INET)
			addr = (&((struct sockaddr_in *)(rp->ai_addr))->sin_addr);
		else
			addr = (&((struct sockaddr_in6 *)(rp->ai_addr))->sin6_addr);

		if (inet_ntop(rp->ai_family, addr, ipname, sizeof(ipname)) != NULL) {
			freeaddrinfo(res);
			return safe_strdup(ipname);
		}
	}

	freeaddrinfo(res);
	return NULL;
}

static int bit_count(uint32_t i)
{
	int c = 0;

	while (i > 0) {
		if (i & 1)
			c++;
		i >>= 1;
	}

	return c;
}

/*!
  \fn int mask2prefix(struct in_addr mask)
  \brief calculates the number of bits masked off by a netmask.

  This function calculates the significant bits in an IP address as specified by
  a netmask.  See also \ref prefix2mask.

  \param mask is the netmask, specified as an struct in_addr in network byte order.
  \return the number of significant bits.  */
static int mask2prefix(struct in_addr mask)
{
	int c = 0;
	unsigned int seen_one = 0;
	uint32_t i = ntohl(mask.s_addr);

	while (i > 0) {
		if (i & 1) {
			seen_one = 1;
			c++;
		} else {
			if (seen_one) {
				return -1;
			}
		}
		i >>= 1;
	}

	return c;
}

static
int ipv4_mask_to_int(const char *prefix)
{
	int ret;
	struct in_addr in;

	ret = inet_pton(AF_INET, prefix, &in);
	if (ret == 0)
		return -1;

	return mask2prefix(in);
}

/* Returns powers of two in textual format */
static const char *p2_table(unsigned pow)
{
	static const char *pow2[] = {
		"1",
		"2",
		"4",
		"8",
		"16",
		"32",
		"64",
		"128",
		"256",
		"512",
		"1024",
		"2048",
		"4096",
		"8192",
		"16384",
		"32768",
		"65536",
		"131072",
		"262144",
		"524288",
		"1048576",
		"2097152",
		"4194304",
		"8388608",
		"16777216",
		"33554432",
		"67108864",
		"134217728",
		"268435456",
		"536870912",
		"1073741824",
		"2147483648",
		"4294967296",
		"8589934592",
		"17179869184",
		"34359738368",
		"68719476736",
		"137438953472",
		"274877906944",
		"549755813888",
		"1099511627776",
		"2199023255552",
		"4398046511104",
		"8796093022208",
		"17592186044416",
		"35184372088832",
		"70368744177664",
		"140737488355328",
		"281474976710656",
		"562949953421312",
		"1125899906842624",
		"2251799813685248",
		"4503599627370496",
		"9007199254740992",
		"18014398509481984",
		"36028797018963968",
		"72057594037927936",
		"144115188075855872",
		"288230376151711744",
		"576460752303423488",
		"1152921504606846976",
		"2305843009213693952",
		"4611686018427387904",
		"9223372036854775808",
		"18446744073709551616",
		"36893488147419103232",
		"73786976294838206464",
		"147573952589676412928",
		"295147905179352825856",
		"590295810358705651712",
		"1180591620717411303424",
		"2361183241434822606848",
		"4722366482869645213696",
		"9444732965739290427392",
		"18889465931478580854784",
		"37778931862957161709568",
		"75557863725914323419136",
		"151115727451828646838272",
		"302231454903657293676544",
		"604462909807314587353088",
		"1208925819614629174706176",
		"2417851639229258349412352",
		"4835703278458516698824704",
		"9671406556917033397649408",
		"19342813113834066795298816",
		"38685626227668133590597632",
		"77371252455336267181195264",
		"154742504910672534362390528",
		"309485009821345068724781056",
		"618970019642690137449562112",
		"1237940039285380274899124224",
		"2475880078570760549798248448",
		"4951760157141521099596496896",
		"9903520314283042199192993792",
		"19807040628566084398385987584",
		"39614081257132168796771975168",
		"79228162514264337593543950336",
		"158456325028528675187087900672",
		"316912650057057350374175801344",
		"633825300114114700748351602688",
		"1267650600228229401496703205376",
		"2535301200456458802993406410752",
		"5070602400912917605986812821504",
		"10141204801825835211973625643008",
		"20282409603651670423947251286016",
		"40564819207303340847894502572032",
		"81129638414606681695789005144064",
		"162259276829213363391578010288128",
		"324518553658426726783156020576256",
		"649037107316853453566312041152512",
		"1298074214633706907132624082305024",
		"2596148429267413814265248164610048",
		"5192296858534827628530496329220096",
		"10384593717069655257060992658440192",
		"20769187434139310514121985316880384",
		"41538374868278621028243970633760768",
		"83076749736557242056487941267521536",
		"166153499473114484112975882535043072",
		"332306998946228968225951765070086144",
		"664613997892457936451903530140172288",
		"1329227995784915872903807060280344576",
		"2658455991569831745807614120560689152",
		"5316911983139663491615228241121378304",
		"10633823966279326983230456482242756608",
		"21267647932558653966460912964485513216",
		"42535295865117307932921825928971026432",
		"85070591730234615865843651857942052864",
		"170141183460469231731687303715884105728",
	};
	if (pow <= 127)
		return pow2[pow];
	return "";
}

static const char *ipv4_net_to_type(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;
	unsigned byte2 = (ntohl(net.s_addr) >> 16) & 0xff;
	unsigned byte3 = (ntohl(net.s_addr) >> 8) & 0xff;
	unsigned byte4 = (ntohl(net.s_addr)) & 0xff;

	/* based on IANA's iana-ipv4-special-registry and ipv4-address-space
	 * Updated: 2020-04-06
	 */
	if (byte1 == 0) {
		return "This host on this network";
	}

	if (byte1 == 10) {
		return "Private Use";
	}

	if (byte1 == 100 && (byte2 & 0xc0) == 64) {
		return "Shared Address Space";
	}

	if (byte1 == 127) {
		return "Loopback";
	}

	if (byte1 == 169 && byte2 == 254) {
		return "Link Local";
	}

	if (byte1 == 172 && (byte2 & 0xf0) == 16) {
		return "Private Use";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0 && byte4 <= 7) {
		return "IPv4 Service Continuity Prefix";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0 && byte4 == 8) {
		return "IPv4 dummy address";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0 && byte4 == 9) {
		return "Port Control Protocol Anycast";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0 && byte4 == 10) {
		return "Traversal Using Relays around NAT Anycast";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0 && (byte4 == 170 || byte4 == 171)) {
		return "NAT64/DNS64 Discovery";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0) {
		return "IETF Protocol Assignments";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 2) {
		return "Documentation (TEST-NET-1)";
	}

	if (byte1 == 198 && byte2 == 51 && byte3 == 100) {
		return "Documentation (TEST-NET-2)";
	}

	if (byte1 == 203 && byte2 == 0 && byte3 == 113) {
		return "Documentation (TEST-NET-3)";
	}

	if (byte1 == 192 && byte2 == 88 && byte3 == 99) {
		return "6 to 4 Relay Anycast (Deprecated)";
	}

	if (byte1 == 192 && byte2 == 31 && byte3 == 196) {
		return "AS112-v4";
	}

	if (byte1 == 192 && byte2 == 52 && byte3 == 193) {
		return "AMT";
	}

	if (byte1 == 192 && byte2 == 168) {
		return "Private Use";
	}

	if (byte1 == 192 && byte2 == 175 && byte3 == 48) {
		return "Direct Delegation AS112 Service";
	}

	if (byte1 == 255 && byte2 == 255 && byte3 == 255 && byte4 == 255) {
		return "Limited Broadcast";
	}

	if (byte1 == 198 && (byte2 & 0xfe) == 18) {
		return "Benchmarking";
	}

	if (byte1 >= 224 && byte1 <= 239) {
		return "Multicast";
	}

	if ((byte1 & 0xf0) == 240) {
		return "Reserved";
	}

	return "Internet";
}

static
const char *ipv4_net_to_class(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;

	if (byte1 < 128) {
		return "Class A";
	}

	if (byte1 >= 128 && byte1 < 192) {
		return "Class B";
	}

	if (byte1 >= 192 && byte1 < 224) {
		return "Class C";
	}

	if (byte1 >= 224 && byte1 < 239) {
		return "Class D";
	}

	return "Class E";
}

static
unsigned default_ipv4_prefix(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;

	if (byte1 < 128) {
		return 8;
	}

	if (byte1 >= 128 && byte1 < 192) {
		return 16;
	}

	if (byte1 >= 192 && byte1 < 224) {
		return 24;
	}

	return 24;
}

char *ipv4_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix)
{
	if (prefix >= 31) {
		snprintf(hosts, hosts_size, "%s", p2_table(32 - prefix));
	} else {
		unsigned tmp = (1 << (32 - prefix)) - 2;
		snprintf(hosts, hosts_size, "%u", tmp);
	}
	return hosts;
}

char *ipv6_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix)
{
	snprintf(hosts, hosts_size, "%s", p2_table(128 - prefix));
	return hosts;
}


static
int get_ipv4_info(const char *ipStr, int prefix, ip_info_st * info,
		  unsigned flags)
{
	struct in_addr ip, netmask, network, broadcast, minhost, maxhost;
	char namebuf[INET_ADDRSTRLEN + 1];
	char errBuf[250];

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET, ipStr, &ip) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 address: %s\n",
				ipStr);
		return -1;
	}

	/* Handle CIDR entries such as 172/8 */
	if (prefix >= 0) {
		char *tmp = (char *)ipStr;
		int i;

		for (i = 3; i > 0; i--) {
			tmp = strchr(tmp, '.');
			if (!tmp)
				break;
			else
				tmp++;
		}

		tmp = NULL;
		for (; i > 0; i--) {
			if (asprintf(&tmp, "%s.0", ipStr) == -1) {
				fprintf(stderr,
					"Memory allocation failure line %d\n",
					__LINE__);
				abort();
			}
			ipStr = tmp;
		}
	} else { /* assume good old days classful Internet */
		if (flags & FLAG_ASSUME_CLASS_PREFIX)
			prefix = default_ipv4_prefix(ip);
		else
			prefix = 32;
	}

	if (prefix > 32) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 prefix %d\n", prefix);
		return -1;
	}

	if (inet_ntop(AF_INET, &ip, namebuf, sizeof(namebuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv4 network\n");
		return -1;
	}
	info->ip = safe_strdup(namebuf);

	netmask.s_addr = prefix2mask(prefix);
	memset(namebuf, '\0', sizeof(namebuf));

	if (inet_ntop(AF_INET, &netmask, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "inet_ntop failure at line %d\n",
			__LINE__);
		exit(1);
	}
	info->netmask = safe_strdup(namebuf);
	info->prefix = prefix;

	broadcast = calc_broadcast(ip, prefix);

	memset(namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &broadcast, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "inet_ntop failure at line %d\n",
			__LINE__);
		exit(1);
	}
	info->broadcast = safe_strdup(namebuf);

	network = calc_network(ip, prefix);

	info->reverse_dns = calc_reverse_dns4(network, prefix, network, broadcast);

	memset(namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &network, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "inet_ntop failure at line %d\n",
			__LINE__);
		exit(1);
	}

	info->network = safe_strdup(namebuf);

	info->type = ipv4_net_to_type(network);
	info->class = ipv4_net_to_class(network);

	if (prefix < 32) {
		memcpy(&minhost, &network, sizeof(minhost));

		if (prefix <= 30)
			minhost.s_addr = htonl(ntohl(minhost.s_addr) | 1);
		if (inet_ntop(AF_INET, &minhost, namebuf, INET_ADDRSTRLEN) ==
		    NULL) {
			fprintf(stderr, "inet_ntop failure at line %d\n",
				__LINE__);
			exit(1);
		}
		info->hostmin = safe_strdup(namebuf);

		memcpy(&maxhost, &network, sizeof(minhost));
		maxhost.s_addr |= ~netmask.s_addr;
		if (prefix <= 30) {
			maxhost.s_addr = htonl(ntohl(maxhost.s_addr) - 1);
		}
		if (inet_ntop(AF_INET, &maxhost, namebuf, sizeof(namebuf)) == 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: error calculating the IPv4 network\n");
			return -1;
		}

		info->hostmax = safe_strdup(namebuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	ipv4_prefix_to_hosts(info->hosts, sizeof(info->hosts), prefix);

#if defined(USE_GEOIP) || defined(USE_MAXMIND)
	if (flags & FLAG_GET_GEOIP) {
		geo_ip_lookup(ipStr, &info->geoip_country, &info->geoip_ccode, &info->geoip_city, &info->geoip_coord);
	}
#endif

	if (flags & FLAG_RESOLVE_HOST) {
		info->hostname = get_hostname(AF_INET, &ip);
		if (info->hostname == NULL) {
			if (!beSilent) {
				sprintf(errBuf,
					"ipcalc: cannot find hostname for %s",
					ipStr);
				herror(errBuf);
			}
			return -1;
		}
	}
	return 0;
}

int ipv6_prefix_to_mask(unsigned prefix, struct in6_addr *mask)
{
	struct in6_addr in6;
	int i, j;

	if (prefix > 128)
		return -1;

	memset(&in6, 0x0, sizeof(in6));
	for (i = prefix, j = 0; i > 0; i -= 8, j++) {
		if (i >= 8) {
			in6.s6_addr[j] = 0xff;
		} else {
			in6.s6_addr[j] = (unsigned long)(0xffU << (8 - i));
		}
	}

	memcpy(mask, &in6, sizeof(*mask));
	return 0;
}

static char *ipv6_mask_to_str(const struct in6_addr *mask)
{
	char buf[128];

	if (inet_ntop(AF_INET6, mask, buf, sizeof(buf)) == NULL)
		return NULL;

	return safe_strdup(buf);
}

static const char *ipv6_net_to_type(struct in6_addr *net, int prefix)
{
	uint16_t word1 = net->s6_addr[0] << 8 | net->s6_addr[1];
	uint16_t word2 = net->s6_addr[2] << 8 | net->s6_addr[3];

	/* based on IANA's iana-ipv6-special-registry and ipv6-address-space
	 * Updated: 2019-09-13
	 */
	if (prefix == 128 && memcmp
	    (net->s6_addr,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	     16) == 0)
		return "Loopback Address";

	if (prefix == 128 && memcmp
	    (net->s6_addr,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	     16) == 0)
		return "Unspecified Address";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",
	     12) == 0)
		return "IPv4-mapped Address";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00",
	     12) == 0)
		return "IPv4-IPv6 Translat.";

	if (prefix >= 48 && memcmp
	    (net->s6_addr, "\x00\x64\xff\x9b\x00\x01",
	     6) == 0)
		return "IPv4-IPv6 Translat.";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	     12) == 0)
		return "Discard-Only Address Block";

	if (prefix >= 32 && word1 == 0x2001 && word2 == 0)
		return "TEREDO";

	if (prefix == 128 && memcmp
	    (net->s6_addr, "\x20\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	     16) == 0)
		return "Port Control Protocol Anycast";

	if (prefix == 128 && memcmp
	    (net->s6_addr, "\x20\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
	     16) == 0)
		return "Traversal Using Relays around NAT Anycast";

	if (prefix >= 48 && memcmp
	    (net->s6_addr, "\x20\x01\x00\x02\x00\x00",
	     6) == 0)
		return "Benchmarking";

	if (prefix >= 32 && word1 == 0x2001 && word2 == 0x3)
		return "AMT";

	if (prefix >= 48 && memcmp
	    (net->s6_addr, "\x20\x01\x00\x04\x01\x12",
	     6) == 0)
		return "AS112-v6";

	if (prefix >= 28 && word1 == 0x2001 && (word2 & 0xfff0) == 0x10)
		return "Deprecated (previously ORCHID)";

	if (prefix >= 28 && word1 == 0x2001 && (word2 & 0xfff0) == 0x20)
		return "ORCHIDv2";

	if (prefix >= 23 && word1 == 0x2001 && (word2 & 0xff00) <= 0x100)
		return "IETF Protocol Assignments";

	if (prefix >= 32 && word1 == 0x2001 && word2 == 0xdb8)
		return "Documentation";

	if (word1 == 0x2002)
		return "6to4";

	if (prefix >= 48 && memcmp
	    (net->s6_addr, "\x26\x20\x00\x4f\x80\x00",
	     6) == 0)
		return "Direct Delegation AS112 Service";

	if ((word1 & 0xe000) == 0x2000) {
		return "Global Unicast";
	}

	if (((net->s6_addr[0] & 0xfe) == 0xfc)) {
		return "Unique Local Unicast";
	}

	if ((word1 & 0xffc0) == 0xfe80) {
		return "Link-Scoped Unicast";
	}

	if ((net->s6_addr[0] & 0xff) == 0xff) {
		return "Multicast";
	}

	return "Reserved";
}

static
char *expand_ipv6(struct in6_addr *ip6)
{
	char buf[128];
	char *p;
	unsigned i;

	p = buf;
	for (i = 0; i < 16; i++) {
		sprintf(p, "%.2x", (unsigned)ip6->s6_addr[i]);
		p += 2;
		if (i % 2 != 0 && i != 15) {
			*p = ':';
			p++;
		}
	}
	*p = 0;

	return safe_strdup(buf);
}

static
int get_ipv6_info(const char *ipStr, int prefix, ip_info_st * info,
		  unsigned flags)
{
	struct in6_addr ip6, mask, network;
	char errBuf[250];
	unsigned i;

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET6, ipStr, &ip6) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n",
				ipStr);
		return -1;
	}

	/* expand  */
	info->expanded_ip = expand_ipv6(&ip6);

	if (inet_ntop(AF_INET6, &ip6, errBuf, sizeof(errBuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv6 network\n");
		return -1;
	}

	info->ip = safe_strdup(errBuf);

	if (prefix > 128) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 prefix: %d\n",
				prefix);
		return -1;
	} else if (prefix < 0) {
		prefix = 128;
	}

	info->prefix = prefix;

	if (ipv6_prefix_to_mask(prefix, &mask) == -1) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error converting IPv6 prefix: %d\n",
				prefix);
		return -1;
	}

	info->netmask = ipv6_mask_to_str(&mask);

	for (i = 0; i < sizeof(struct in6_addr); i++)
		network.s6_addr[i] = ip6.s6_addr[i] & mask.s6_addr[i];

	if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv6 network\n");
		return -1;
	}

	info->network = safe_strdup(errBuf);

	info->expanded_network = expand_ipv6(&network);
	info->type = ipv6_net_to_type(&network, prefix);

	info->reverse_dns = calc_reverse_dns6(&network, prefix);

	if (prefix < 128) {
		info->hostmin = safe_strdup(errBuf);

		for (i = 0; i < sizeof(struct in6_addr); i++)
			network.s6_addr[i] |= ~mask.s6_addr[i];
		if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: error calculating the IPv6 network\n");
			return -1;
		}

		info->hostmax = safe_strdup(errBuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	ipv6_prefix_to_hosts(info->hosts, sizeof(info->hosts), prefix);

#if defined(USE_GEOIP) || defined(USE_MAXMIND)
	if (flags & FLAG_GET_GEOIP) {
		geo_ip_lookup(ipStr, &info->geoip_country, &info->geoip_ccode, &info->geoip_city, &info->geoip_coord);
	}
#endif

	if (flags & FLAG_RESOLVE_HOST) {
		info->hostname = get_hostname(AF_INET6, &ip6);
		if (info->hostname == NULL) {
			if (!beSilent) {
				sprintf(errBuf,
					"ipcalc: cannot find hostname for %s",
					ipStr);
				herror(errBuf);
			}
			return -1;
		}
	}
	return 0;
}

static int randomize(void *ptr, unsigned size)
{
	int fd, ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, ptr, size);
	close(fd);

	if (ret != size) {
		return -1;
	}

	return 0;
}

static char *generate_ip_network(unsigned prefix, unsigned flags)
{
	struct timespec ts;
	char ipbuf[64];
	char *p = NULL;

	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) < 0)
		return NULL;

	if (flags & FLAG_IPV6) {
		struct in6_addr net;

		net.s6_addr[0] = 0xfd;
		if (randomize(&net.s6_addr[1], 15) < 0)
			return NULL;

		if (inet_ntop(AF_INET6, &net, ipbuf, sizeof(ipbuf)) == NULL)
			return NULL;
	} else {
		struct in_addr net;
		unsigned c = ts.tv_nsec % 4;
		uint8_t bytes[4];

		if (randomize(bytes, 4) < 0)
			return NULL;

		if (prefix >= 16 && c < 2) {
			if (c == 1) {
				bytes[0] = 192;
				bytes[1] = 168;
			} else {
				bytes[0] = 172;
				bytes[1] = 16 | ((ts.tv_nsec >> 4) & 0x0f);
			}
		} else {
			bytes[0] = 10;
		}

		memcpy(&net.s_addr, bytes, 4);

		if (inet_ntop(AF_INET, &net, ipbuf, sizeof(ipbuf)) == NULL)
			return NULL;
	}

	if (asprintf(&p, "%s/%u", ipbuf, prefix) == -1)
		return NULL;

	return p;
}

static
int str_to_prefix(unsigned *flags, const char *prefixStr, unsigned fix)
{
	int prefix = -1;
	if (!((*flags) & FLAG_IPV6) && strchr(prefixStr, '.')) {	/* prefix is 255.x.x.x */
		prefix = ipv4_mask_to_int(prefixStr);
	} else {
		int r = safe_atoi(prefixStr, &prefix);
		if (r != 0) {
			return -1;
		}
	}

	if (fix && (prefix > 32 && !((*flags) & FLAG_IPV6)))
		*flags |= FLAG_IPV6;

	if (prefix < 0 || ((((*flags) & FLAG_IPV6) && prefix > 128) || (!((*flags) & FLAG_IPV6) && prefix > 32))) {
		return -1;
	}
	return prefix;
}

#define OPT_ALLINFO 1
#define OPT_MINADDR 2
#define OPT_MAXADDR 3
#define OPT_ADDRESSES 4
#define OPT_ADDRSPACE 5
#define OPT_USAGE 6
#define OPT_REVERSE 7
#define OPT_CLASS_PREFIX 8
#define OPT_NO_DECORATE 9

static const struct option long_options[] = {
	{"check", 0, 0, 'c'},
	{"random-private", 1, 0, 'r'},
	{"split", 1, 0, 'S'},
	{"deaggregate", 1, 0, 'd'},
	{"info", 0, 0, 'i'},
	{"all-info", 0, 0, OPT_ALLINFO},
	{"ipv4", 0, 0, '4'},
	{"ipv6", 0, 0, '6'},
	{"address", 0, 0, 'a'},
	{"broadcast", 0, 0, 'b'},
	{"hostname", 0, 0, 'h'},
	{"lookup-host", 1, 0, 'o'},
	{"reverse-dns", 0, 0, OPT_REVERSE},
#if defined(USE_GEOIP) || defined(USE_MAXMIND)
	{"geoinfo", 0, 0, 'g'},
#endif
	{"netmask", 0, 0, 'm'},
	{"network", 0, 0, 'n'},
	{"prefix", 0, 0, 'p'},
	{"class-prefix", 0, 0, OPT_CLASS_PREFIX},
	{"minaddr", 0, 0, OPT_MINADDR},
	{"maxaddr", 0, 0, OPT_MAXADDR},
	{"addresses", 0, 0, OPT_ADDRESSES},
	{"addrspace", 0, 0, OPT_ADDRSPACE},
	{"silent", 0, 0, 's'},
	{"no-decorate", 0, 0, OPT_NO_DECORATE},
	{"json", 0, 0, 'j'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, '?'},
	{"usage", 0, 0, OPT_USAGE},
	{NULL, 0, 0, 0}
};

static
void usage(unsigned verbose)
{
	if (verbose) {
		fprintf(stderr, "Usage: ipcalc [OPTION...]\n");
		fprintf(stderr, "  -c, --check                     Validate IP address\n");
		fprintf(stderr, "  -r, --random-private=PREFIX     Generate a random private IP network using\n");
		fprintf(stderr, "                                  the supplied prefix or mask.\n");
		fprintf(stderr, "  -S, --split=PREFIX              Split the provided network using the\n");
		fprintf(stderr, "                                  provided prefix/netmask\n");
		fprintf(stderr, "  -d, --deaggregate=IP1-IP2       Deaggregate the provided address range\n");
		fprintf(stderr, "  -i, --info                      Print information on the provided IP address\n");
		fprintf(stderr, "                                  (default)\n");
		fprintf(stderr, "      --all-info                  Print verbose information on the provided IP\n");
		fprintf(stderr, "                                  address\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "Specific info options:\n");
		fprintf(stderr, "      --reverse-dns               Print network in a the reverse DNS format\n");
		fprintf(stderr, "  -a, --address                   Display IP address\n");
		fprintf(stderr, "  -b, --broadcast                 Display calculated broadcast address\n");
		fprintf(stderr, "  -m, --netmask                   Display netmask for IP\n");
		fprintf(stderr, "  -n, --network                   Display network address\n");
		fprintf(stderr, "  -p, --prefix                    Display network prefix\n");
		fprintf(stderr, "      --minaddr                   Display the minimum address in the network\n");
		fprintf(stderr, "      --maxaddr                   Display the maximum address in the network\n");
		fprintf(stderr, "      --addresses                 Display the maximum number of addresses in\n");
		fprintf(stderr, "                                  the network\n");
		fprintf(stderr, "      --addrspace                 Display the address space the network\n");
		fprintf(stderr, "                                  resides on\n");
		fprintf(stderr, "  -h, --hostname                  Show hostname determined via DNS\n");
		fprintf(stderr, "  -o, --lookup-host=STRING        Show IP as determined via DNS\n");
#if defined(USE_GEOIP) || defined(USE_MAXMIND)
		fprintf(stderr, "  -g, --geoinfo                   Show Geographic information about the\n");
		fprintf(stderr, "                                  provided IP\n");
#endif
		fprintf(stderr, "\n");
		fprintf(stderr, "Other options:\n");
		fprintf(stderr, "  -4, --ipv4                      Explicitly specify the IPv4 address family\n");
		fprintf(stderr, "  -6, --ipv6                      Explicitly specify the IPv6 address family\n");
		fprintf(stderr, "      --class-prefix              When specified the default prefix will be determined\n");
		fprintf(stderr, "                                  by the IPv4 address class\n");
		fprintf(stderr, "      --no-decorate               Print only the requested information\n");
		fprintf(stderr, "  -j, --json                      JSON output\n");
		fprintf(stderr, "  -s, --silent                    Don't ever display error messages\n");
		fprintf(stderr, "  -v, --version                   Display program version\n");
		fprintf(stderr, "  -?, --help                      Show this help message\n");
		fprintf(stderr, "      --usage                     Display brief usage message\n");
	} else {
		fprintf(stderr, "Usage: ipcalc [-46sv?] [-c|--check] [-r|--random-private=STRING] [-i|--info]\n");
		fprintf(stderr, "        [--all-info] [-4|--ipv4] [-6|--ipv6] [-a|--address] [-b|--broadcast]\n");
		fprintf(stderr, "        [-h|--hostname] [-o|--lookup-host=STRING] [-g|--geoinfo]\n");
		fprintf(stderr, "        [-m|--netmask] [-n|--network] [-p|--prefix] [--minaddr] [--maxaddr]\n");
		fprintf(stderr, "        [--addresses] [--addrspace] [-j|--json] [-s|--silent] [-v|--version]\n");
		fprintf(stderr, "        [--reverse-dns] [--class-prefix]\n");
		fprintf(stderr, "        [-?|--help] [--usage]\n");
	}
}

void output_start(unsigned * const jsonfirst)
{
	if (flags & FLAG_JSON) {
		printf("{\n");
	}

	*jsonfirst = JSON_FIRST;
}

void output_separate(unsigned * const jsonfirst)
{
	if (!(flags & FLAG_JSON)) {
		printf("\n");
	}
}

void output_stop(unsigned * const jsonfirst)
{
	if (flags & FLAG_JSON) {
		printf("\n}\n");
	}
}

void array_start(unsigned * const jsonfirst, const char *head, const char *json_head)
{
	if (flags & FLAG_JSON) {
		if (*jsonfirst == JSON_NEXT) {
			printf(",\n  ");
		}

		printf("  \"%s\":[\n  ", json_head);
	} else {
		if (!(flags & FLAG_NO_DECORATE))
			printf("[%s]\n", head);
	}

	*jsonfirst = JSON_ARRAY_FIRST;
}

void array_stop(unsigned * const jsonfirst)
{
	if (flags & FLAG_JSON) {
		printf("]");
		*jsonfirst = JSON_NEXT;
	}
}

void
__attribute__ ((format(printf, 3, 4)))
color_printf(const char *color, const char *title, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	va_color_printf(color, title, fmt, args);
	va_end(args);

	return;
}

void va_color_printf(const char *color, const char *title, const char *fmt, va_list varglist)
{
	int ret;
	char *str = NULL;

	ret = vasprintf(&str, fmt, varglist);

	if (ret < 0) {
		return;
	}

	fputs(title, stdout);
	if (colors) {
		fputs(color, stdout);
	}
	fputs(str, stdout);
	fputs("\n", stdout);
	if (colors) {
		fputs(KRESET, stdout);
	}
	free(str);
	return;
}

void
__attribute__ ((format(printf, 3, 4)))
json_printf(unsigned * const jsonfirst, const char *jsontitle, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	va_json_printf(jsonfirst, jsontitle, fmt, args);
	va_end(args);

	return;
}
void va_json_printf(unsigned * const jsonfirst, const char *jsontitle, const char *fmt, va_list varglist)
{
	int ret;
	char *str = NULL;

	ret = vasprintf(&str, fmt, varglist);
	if (ret < 0)
		return;

	if (*jsonfirst == JSON_ARRAY_NEXT) {
		fprintf(stdout, ",\n  ");
	} else if (*jsonfirst == JSON_NEXT) {
		fprintf(stdout, ",\n");
	}

	fprintf(stdout, "  ");
	if (jsontitle)
		fprintf(stdout, "\"%s\":\"%s\"", jsontitle, str);
	else
		fprintf(stdout, "\"%s\"", str);
	if (*jsonfirst == JSON_FIRST)
		*jsonfirst = JSON_NEXT;
	else if (*jsonfirst == JSON_ARRAY_FIRST)
		*jsonfirst = JSON_ARRAY_NEXT;

	free(str);
	return;
}

/* Always prints "title: value", will not color if --no-decorate is given
 */
static void
__attribute__ ((format(printf, 4, 5)))
pretty_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (flags & FLAG_JSON) {
		va_json_printf(jsonfirst, jsontitle, fmt, args);
	} else if (flags & FLAG_NO_DECORATE) {
		fputs(title, stdout);
		vprintf(fmt, args);
		fputs("\n", stdout);
	} else {
		va_color_printf(KBLUE, title, fmt, args);
	}
	va_end(args);

	return;
}

/* Always prints "title: value", will not color if --no-decorate is given
 * To be used for distinct values (e.g., a summary).
 */
static void
__attribute__ ((format(printf, 4, 5)))
pretty_dist_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (flags & FLAG_JSON) {
		va_json_printf(jsonfirst, jsontitle, fmt, args);
	} else if (flags & FLAG_NO_DECORATE) {
		fputs(title, stdout);
		vprintf(fmt, args);
		fputs("\n", stdout);
	} else {
		va_color_printf(KMAG, title, fmt, args);
	}
	va_end(args);

	return;
}

/* Prints "title: value", will only print value if --no-decorate is given
 */
void
__attribute__ ((format(printf, 4, 5)))
default_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (flags & FLAG_JSON) {
		va_json_printf(jsonfirst, jsontitle, fmt, args);
	} else if (flags & FLAG_NO_DECORATE) {
		vprintf(fmt, args);
		printf("\n");
	} else {
		va_color_printf(KBLUE, title, fmt, args);
	}
	va_end(args);

	return;
}

/* Prints "title: value", will only print value if --no-decorate is given. It
 * prints a distinct value (e.g., to be used for a summary).
 */
void
__attribute__ ((format(printf, 4, 5)))
dist_printf(unsigned * const jsonfirst, const char *title, const char *jsontitle, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (flags & FLAG_JSON) {
		va_json_printf(jsonfirst, jsontitle, fmt, args);
	}
	else if (flags & FLAG_NO_DECORATE) {
		vprintf(fmt, args);
		printf("\n");
	} else {
		va_color_printf(KMAG, title, fmt, args);
	}
	va_end(args);

	return;
}

/* Printed variables names */
#define HOSTNAME_NAME "HOSTNAME"
#define FULL_ADDRESS_NAME "FULLADDRESS"
#define ADDRESS_NAME "ADDRESS"
#define FULL_NETWORK_NAME "FULLNETWORK"
#define NETWORK_NAME "NETWORK"
#define NETMASK_NAME "NETMASK"
#define PREFIX_NAME "PREFIX"
#define BROADCAST_NAME "BROADCAST"
#define REVERSEDNS_NAME "REVERSEDNS"
#define ADDRSPACE_NAME "ADDRSPACE"
#define ADDRCLASS_NAME "ADDRCLASS"
#define MINADDR_NAME "MINADDR"
#define MAXADDR_NAME "MAXADDR"
#define ADDRESSES_NAME "ADDRESSES"
#define COUNTRYCODE_NAME "COUNTRYCODE"
#define COUNTRY_NAME "COUNTRY"
#define CITY_NAME "CITY"
#define COORDINATES_NAME "COORDINATES"

/*!
  \fn main(int argc, const char **argv)
  \brief wrapper program for ipcalc functions.

  This is a wrapper program for the functions that the ipcalc library provides.
  It can be used from shell scripts or directly from the command line.

  For more information, please see the ipcalc(1) man page.
*/
// int main(int argc, char **argv)
// {
// 	char *randomStr = NULL;
// 	char *hostname = NULL;
// 	char *splitStr = NULL;
// 	char *ipStr = NULL, *prefixStr = NULL, *netmaskStr = NULL, *chptr = NULL;
// 	int prefix = -1, splitPrefix = -1;
// 	ip_info_st info;
// 	int r = 0;
// 	unsigned jsonchain = JSON_FIRST;
// 	enum app_t app = 0;

// 	while (1) {
// 		int c = getopt_long(argc, argv, "S:cr:i46abho:gmnpjsvd:", long_options, NULL);
// 		if (c == -1)
// 			break;

// 		switch(c) {
// 			case 'c':
// 				app |= APP_CHECK_ADDRESS;
// 				break;
// 			case 'S':
// 				app |= APP_SPLIT;
// 				splitStr = safe_strdup(optarg);
// 				if (splitStr == NULL) exit(1);
// 				break;
// 			case 'd':
// 				app |= APP_DEAGGREGATE;
// 				ipStr = safe_strdup(optarg);
// 				if (ipStr == NULL) exit(1);
// 				break;
// 			case 'r':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_RANDOM;
// 				randomStr = safe_strdup(optarg);
// 				if (randomStr == NULL) exit(1);
// 				break;
// 			case 'i':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_MODERN_INFO;
// 				break;
// 			case OPT_ALLINFO:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_ALL_INFO|FLAG_SHOW_MODERN_INFO;
// 				break;
// 			case OPT_CLASS_PREFIX:
// 				flags |= FLAG_ASSUME_CLASS_PREFIX;
// 				break;
// 			case OPT_REVERSE:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_REVERSE;
// 				break;
// 			case '4':
// 				flags |= FLAG_IPV4;
// 				break;
// 			case '6':
// 				flags |= FLAG_IPV6;
// 				break;
// 			case 'a':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_ADDRESS;
// 				break;
// 			case 'b':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_BROADCAST;
// 				break;
// 			case 'h':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_RESOLVE_HOST;
// 				break;
// 			case 'o':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_RESOLVE_IP;
// 				hostname = safe_strdup(optarg);
// 				if (hostname == NULL) exit(1);
// 				break;
// 			case 'g':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_GEOIP;
// 				break;
// 			case 'm':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_NETMASK;
// 				break;
// 			case 'n':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_NETWORK;
// 				break;
// 			case 'p':
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_PREFIX;
// 				break;
// 			case OPT_MINADDR:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_MINADDR;
// 				break;
// 			case OPT_MAXADDR:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_MAXADDR;
// 				break;
// 			case OPT_ADDRESSES:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_ADDRESSES;
// 				break;
// 			case OPT_ADDRSPACE:
// 				app |= APP_SHOW_INFO;
// 				flags |= FLAG_SHOW_ADDRSPACE;
// 				break;
// 			case OPT_NO_DECORATE:
// 				flags |= FLAG_NO_DECORATE;
// 				break;
// 			case 'j':
// 				flags |= FLAG_JSON;
// 				break;
// 			case 's':
// 				beSilent = 1;
// 				break;
// 			case 'v':
// 				app |= APP_VERSION;
// 				break;
// 			case OPT_USAGE:
// 				usage(0);
// 				exit(0);
// 			case '?':
// 				usage(1);
// 				exit(0);
// 		}
// 	}

// 	if (optind < argc) {
// 		if (ipStr != NULL) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: superfluous option given\n");
// 			exit(1);
// 		}

// 		ipStr = argv[optind++];
// 		if (optind < argc)
// 			chptr = argv[optind++];
// 	}

// 	if ((flags & FLAG_JSON) && (flags & FLAG_NO_DECORATE)) {
// 		flags &= ~FLAG_NO_DECORATE;
// 	}

// 	if (!(flags & FLAGS_TO_IGNORE_MASK))
// 		flags |= FLAG_SHOW_MODERN_INFO;

// 	/* Only the modern info flag results to JSON output */
// 	if ((flags & ENV_INFO_MASK) && (flags & FLAG_JSON))
// 		flags |= FLAG_SHOW_MODERN_INFO;

// 	if (geo_setup() == 0 && (flags & FLAG_SHOW_ALL_INFO))
// 		flags |= FLAG_GET_GEOIP;

// 	if (bit_count(app) > 1) {
// 		if (!beSilent)
// 			fprintf(stderr,
// 				"ipcalc: you cannot mix these options\n");
// 		return 1;
// 	}

// 	if ((flags & FLAG_IPV6) && (flags & FLAG_IPV4)) {
// 		if (!beSilent)
// 			fprintf(stderr,
// 				"ipcalc: you cannot specify both IPv4 and IPv6\n");
// 		return 1;
// 	}

// 	/* if there is a : in the address, it is an IPv6 address.
// 	 * Note that we allow -4, and -6 to be given explicitly, so
// 	 * that the tool can be used to check for a valid IPv4 or IPv6
// 	 * address.
// 	 */
// 	if ((flags & FLAG_IPV4) == 0 && ipStr && strchr(ipStr, ':') != NULL) {
// 		flags |= FLAG_IPV6;
// 	}

// 	switch (app) {
// 	case APP_VERSION:
// 		printf("ipcalc %s\n", VERSION);
// 		return 0;
// 	case APP_DEAGGREGATE:
// 		deaggregate(ipStr, flags);
// 		return 0;
// 	case APP_SPLIT:
// 	case APP_CHECK_ADDRESS:
// 	case APP_SHOW_INFO:
// 		/* These are handled lower into the info app */
// 		break;
// 	}

// 	/* The main application which displays information about an address or
// 	 * a network. */
// 	if (flags & FLAG_RANDOM) {
// 		if (ipStr) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: provided superfluous parameter '%s'\n", ipStr);
// 			return 1;
// 		}

// 		prefix = str_to_prefix(&flags, randomStr, 1);
// 		if (prefix < 0) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: bad %s prefix: %s\n", (flags&FLAG_IPV6)?"IPv6":"IPv4", randomStr);
// 			return 1;
// 		}

// 		ipStr = generate_ip_network(prefix, flags);
// 		if (ipStr == NULL) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: cannot generate network with prefix: %u\n",
// 					prefix);
// 			return 1;
// 		}
// 	}

// 	if (hostname == NULL && ipStr == NULL) {
// 		if (!beSilent) {
// 			fprintf(stderr,
// 				"ipcalc: ip address expected\n");
// 			usage(1);
// 		}
// 		return 1;
// 	}

// 	/* resolve IP address if a hostname was given */
// 	if (hostname) {
// 		int family = AF_UNSPEC;
// 		if (flags & FLAG_IPV6)
// 			family = AF_INET6;
// 		else if (flags & FLAG_IPV4)
// 			family = AF_INET;

// 		ipStr = get_ip_address(family, hostname);
// 		if (ipStr == NULL) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: could not resolve %s\n", hostname);
// 			return 1;
// 		}

// 		if ((flags & FLAG_IPV4) == 0 && strchr(ipStr, ':') != NULL) {
// 			flags |= FLAG_IPV6;
// 		}
// 	}

// 	if (chptr) {
// 		if ((flags & FLAG_IPV6) == 0) {
// 			prefixStr = chptr;
// 		} else {
// 			if (!beSilent) {
// 				fprintf(stderr, "ipcalc: unexpected argument: %s\n",
// 					chptr);
// 				usage(1);
// 			}
// 			return 1;
// 		}
// 	}

// 	if (prefixStr == NULL && strchr(ipStr, '/') != NULL) {
// 		prefixStr = strchr(ipStr, '/');
// 		*prefixStr = '\0';	/* fix up ipStr */
// 		prefixStr++;
// 	}

// 	if (prefixStr != NULL) {
// 		prefix = str_to_prefix(&flags, prefixStr, 0);
// 		if (prefix < 0) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: bad %s prefix: %s\n", (flags & FLAG_IPV6)?"IPv6":"IPv4", prefixStr);
// 			return 1;
// 		}
// 	}

// 	if (flags & FLAG_IPV6) {
// 		r = get_ipv6_info(ipStr, prefix, &info, flags);
// 	} else {
// 		if ((flags & FLAG_SHOW_BROADCAST) || (flags & FLAG_SHOW_NETWORK) || (flags & FLAG_SHOW_PREFIX)) {
// 			if (netmaskStr && prefix >= 0) {
// 				if (!beSilent) {
// 					fprintf(stderr,
// 						"ipcalc: both netmask and prefix specified\n");
// 					usage(1);
// 				}
// 				return 1;
// 			}
// 		}

// 		if (prefix == -1 && netmaskStr) {
// 			prefix = ipv4_mask_to_int(netmaskStr);
// 			if (prefix < 0) {
// 				if (!beSilent)
// 					fprintf(stderr,
// 						"ipcalc: bad IPv4 prefix: %s\n", prefixStr);
// 				return 1;
// 			}
// 		}
// 		r = get_ipv4_info(ipStr, prefix, &info, flags);
// 	}

// 	if (r < 0) {
// 		return 1;
// 	}

// 	switch (app) {
// 	case APP_SPLIT:
// 		splitPrefix = str_to_prefix(&flags, splitStr, 1);
// 		if (splitPrefix < 0) {
// 			if (!beSilent)
// 				fprintf(stderr,
// 					"ipcalc: bad %s prefix: %s\n", (flags & FLAG_IPV6)?"IPv6":"IPv4", splitStr);
// 			return 1;
// 		}

// 		if (flags & FLAG_IPV6) {
// 			show_split_networks_v6(splitPrefix, &info, flags);
// 		} else {
// 			show_split_networks_v4(splitPrefix, &info, flags);
// 		}
// 		return 0;
// 	case APP_CHECK_ADDRESS:
// 		return 0;
// 	default:
// 		break;
// 	}

// 	if (isatty(STDOUT_FILENO) != 0)
// 		colors = 1;

// 	/* we know what we want to display now, so display it. */
// 	if (flags & FLAG_SHOW_MODERN_INFO) {
// 		unsigned single_host = 0;

// 		if (((flags & FLAG_IPV6) && info.prefix == 128) ||
// 		    (!(flags & FLAG_IPV6) && info.prefix == 32)) {
// 			single_host = 1;
// 		}

// 		output_start(&jsonchain);

// 		if ((!randomStr || single_host) &&
// 		    (single_host || strcmp(info.network, info.ip) != 0)) {
// 			if (info.expanded_ip) {
// 				pretty_printf(&jsonchain,"Full Address:\t", FULL_ADDRESS_NAME, "%s", info.expanded_ip);
// 			}
// 			pretty_printf(&jsonchain, "Address:\t", ADDRESS_NAME, "%s", info.ip);
// 		}

// 		if (single_host && info.hostname)
// 			pretty_printf(&jsonchain, "Hostname:\t", HOSTNAME_NAME, "%s", info.hostname);

// 		if (!single_host || (flags & FLAG_JSON)) {
// 			if (! (flags & FLAG_JSON)) {
// 				if (info.expanded_network) {
// 					pretty_printf(&jsonchain, "Full Network:\t", FULL_NETWORK_NAME, "%s/%u", info.expanded_network, info.prefix);
// 				}
// 				pretty_printf(&jsonchain, "Network:\t", NETWORK_NAME, "%s/%u", info.network, info.prefix);
// 				pretty_printf(&jsonchain, "Netmask:\t", NETMASK_NAME, "%s = %u", info.netmask, info.prefix);
// 			}
// 			else {
// 				if (info.expanded_network) {
// 					pretty_printf(&jsonchain, "Full Network:\t", FULL_NETWORK_NAME, "%s", info.expanded_network);
// 				}
// 				pretty_printf(&jsonchain, "Network:\t", NETWORK_NAME, "%s", info.network);
// 				pretty_printf(&jsonchain, "Netmask:\t", NETMASK_NAME, "%s", info.netmask);
// 				pretty_printf(&jsonchain, "Prefix:\t", PREFIX_NAME, "%u", info.prefix);
// 			}


// 			if (info.broadcast)
// 				pretty_printf(&jsonchain, "Broadcast:\t", BROADCAST_NAME, "%s", info.broadcast);
// 		}

// 		if ((flags & FLAG_SHOW_ALL_INFO) && info.reverse_dns)
// 			pretty_printf(&jsonchain, "Reverse DNS:\t", REVERSEDNS_NAME, "%s", info.reverse_dns);

// 		if (!single_host || (flags & FLAG_JSON)) {
// 			output_separate(&jsonchain);

// 			if (info.type)
// 				pretty_dist_printf(&jsonchain, "Address space:\t", ADDRSPACE_NAME, "%s", info.type);

// 			if ((flags & FLAG_SHOW_ALL_INFO) && info.class)
// 				pretty_dist_printf(&jsonchain, "Address class:\t", ADDRCLASS_NAME, "%s", info.class);

// 			if (info.hostmin)
// 				pretty_printf(&jsonchain, "HostMin:\t", MINADDR_NAME, "%s", info.hostmin);

// 			if (info.hostmax)
// 				pretty_printf(&jsonchain, "HostMax:\t", MAXADDR_NAME, "%s", info.hostmax);

// 			if ((flags & FLAG_IPV6) && info.prefix < 112 && !(flags & FLAG_JSON))
// 				pretty_printf(&jsonchain, "Hosts/Net:\t", ADDRESSES_NAME, "2^(%u) = %s", 128-info.prefix, info.hosts);
// 			else
// 				pretty_printf(&jsonchain, "Hosts/Net:\t", ADDRESSES_NAME, "%s", info.hosts);

// 		} else {

// 			if (info.type)
// 				pretty_dist_printf(&jsonchain, "Address space:\t", ADDRSPACE_NAME, "%s", info.type);

// 			if ((flags & FLAG_SHOW_ALL_INFO) && info.class)
// 				pretty_dist_printf(&jsonchain, "Address class:\t", ADDRCLASS_NAME, "%s", info.class);
// 		}

// 		if (info.geoip_country || info.geoip_city || info.geoip_coord) {
// 			output_separate(&jsonchain);

// 			if (info.geoip_ccode)
// 				pretty_dist_printf(&jsonchain, "Country code:\t", COUNTRYCODE_NAME, "%s", info.geoip_ccode);
// 			if (info.geoip_country)
// 				pretty_dist_printf(&jsonchain, "Country:\t", COUNTRY_NAME, "%s", info.geoip_country);
// 			if (info.geoip_city)
// 				pretty_dist_printf(&jsonchain, "City:\t\t", CITY_NAME, "%s", info.geoip_city);
// 			if (info.geoip_coord)
// 				pretty_dist_printf(&jsonchain, "Coordinates:\t", COORDINATES_NAME, "%s", info.geoip_coord);
// 		}

// 		output_stop(&jsonchain);

// 	} else if (!(flags & FLAG_SHOW_MODERN_INFO)) {

// 		if (flags & FLAG_SHOW_ADDRESS) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(ADDRESS_NAME"=");
// 			}
// 			printf("%s\n", info.ip);
// 		}

// 		if (flags & FLAG_SHOW_NETMASK) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(NETMASK_NAME"=");
// 			}
// 			printf("%s\n", info.netmask);
// 		}

// 		if (flags & FLAG_SHOW_PREFIX) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(PREFIX_NAME"=");
// 			}
// 			printf("%u\n", info.prefix);
// 		}

// 		if ((flags & FLAG_SHOW_BROADCAST) && !(flags & FLAG_IPV6)) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(BROADCAST_NAME"=");
// 			}
// 			printf("%s\n", info.broadcast);
// 		}

// 		if (flags & FLAG_SHOW_NETWORK) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(NETWORK_NAME"=");
// 			}
// 			printf("%s\n", info.network);
// 		}

// 		if (flags & FLAG_SHOW_REVERSE) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(REVERSEDNS_NAME"=");
// 			}
// 			printf("%s\n", info.reverse_dns);
// 		}

// 		if ((flags & FLAG_SHOW_MINADDR) && info.hostmin) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(MINADDR_NAME"=");
// 			}
// 			printf("%s\n", info.hostmin);
// 		}

// 		if ((flags & FLAG_SHOW_MAXADDR) && info.hostmax) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(MAXADDR_NAME"=");
// 			}
// 			printf("%s\n", info.hostmax);
// 		}

// 		if ((flags & FLAG_SHOW_ADDRSPACE) && info.type) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(ADDRSPACE_NAME"=");
// 			}
// 			if (strchr(info.type, ' ') != NULL)
// 				printf("\"%s\"\n", info.type);
// 			else
// 				printf("%s\n", info.type);
// 		}

// 		if ((flags & FLAG_SHOW_ADDRESSES) && info.hosts[0]) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(ADDRESSES_NAME"=");
// 			}
// 			if (strchr(info.hosts, ' ') != NULL)
// 				printf("\"%s\"\n", info.hosts);
// 			else
// 				printf("%s\n", info.hosts);
// 		}

// 		if ((flags & FLAG_RESOLVE_HOST) && info.hostname) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(HOSTNAME_NAME"=");
// 			}
// 			printf("%s\n", info.hostname);
// 		}

// 		if (flags & FLAG_RESOLVE_IP) {
// 			if (! (flags & FLAG_NO_DECORATE)) {
// 				printf(ADDRESS_NAME"=");
// 			}
// 			printf("%s\n", ipStr);
// 		}

// 		if ((flags & FLAG_SHOW_GEOIP) == FLAG_SHOW_GEOIP) {
// 			if (info.geoip_ccode) {
// 				if (! (flags & FLAG_NO_DECORATE)) {
// 					printf(COUNTRYCODE_NAME"=");
// 				}
// 				printf("%s\n", info.geoip_ccode);
// 			}
// 			if (info.geoip_country) {
// 				if (! (flags & FLAG_NO_DECORATE)) {
// 					printf(COUNTRY_NAME"=");
// 				}
// 				if (strchr(info.geoip_country, ' ') != NULL)
// 					printf("\"%s\"\n", info.geoip_country);
// 				else
// 					printf("%s\n", info.geoip_country);
// 			}
// 			if (info.geoip_city) {
// 				if (! (flags & FLAG_NO_DECORATE)) {
// 					printf(CITY_NAME"=");
// 				}
// 				if (strchr(info.geoip_city, ' ') != NULL) {
// 					printf("\"%s\"\n", info.geoip_city);
// 				} else {
// 					printf("%s\n", info.geoip_city);
// 				}
// 			}
// 			if (info.geoip_coord) {
// 				if (! (flags & FLAG_NO_DECORATE)) {
// 					printf(COORDINATES_NAME"=");
// 				}
// 				printf("\"%s\"\n", info.geoip_coord);
// 			}
// 		}
// 	}

// 	return 0;
// }

