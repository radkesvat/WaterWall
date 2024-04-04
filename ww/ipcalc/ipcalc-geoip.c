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

#ifdef USE_GEOIP

# include <GeoIP.h>
# include <GeoIPCity.h>

#define GEOIP_SILENCE 16	/* fix libgeoip < 1.6.3 */

# ifdef USE_RUNTIME_LINKING
#  include <dlfcn.h>

typedef void (*_GeoIP_setup_dbfilename_func)(void);
typedef GeoIP * (*GeoIP_open_type_func)(int type, int flags);
typedef const char * (*GeoIP_country_name_by_id_func)(GeoIP * gi, int id);
typedef void (*GeoIP_delete_func)(GeoIP * gi);
typedef GeoIPRecord * (*GeoIP_record_by_ipnum_func)(GeoIP * gi, unsigned long ipnum);
typedef int (*GeoIP_id_by_ipnum_func)(GeoIP * gi, unsigned long ipnum);
typedef int (*GeoIP_id_by_ipnum_v6_func)(GeoIP * gi, geoipv6_t ipnum);
typedef GeoIPRecord *(*GeoIP_record_by_ipnum_v6_func)(GeoIP * gi, geoipv6_t ipnum);
typedef const char *(*GeoIP_code_by_id_func)(int id);

static _GeoIP_setup_dbfilename_func p_GeoIP_setup_dbfilename;
static GeoIP_open_type_func pGeoIP_open_type;
static GeoIP_country_name_by_id_func pGeoIP_country_name_by_id;
static GeoIP_code_by_id_func pGeoIP_code_by_id;
static GeoIP_delete_func pGeoIP_delete;
static GeoIP_record_by_ipnum_func pGeoIP_record_by_ipnum;
static GeoIP_id_by_ipnum_func pGeoIP_id_by_ipnum;
static GeoIP_id_by_ipnum_v6_func pGeoIP_id_by_ipnum_v6;
static GeoIP_record_by_ipnum_v6_func pGeoIP_record_by_ipnum_v6;

#define LIBNAME LIBPATH"/libGeoIP.so.1"

int geo_setup(void)
{
	static void *ld = NULL;
	static int ret = 0;
	static char err[256] = {0};

	if (ld != NULL || ret != 0) {
	    	if (!beSilent && err[0] != 0) {
	    		fprintf(stderr, "%s", err);
		}
		return ret;
	}

	ld = dlopen(LIBNAME, RTLD_LAZY);
	if (ld == NULL) {
		snprintf(err, sizeof(err), "ipcalc: could not open %s\n", LIBNAME);
		ret = -1;
		goto exit;
	}

	p_GeoIP_setup_dbfilename = dlsym(ld, "_GeoIP_setup_dbfilename");

	pGeoIP_open_type = dlsym(ld, "GeoIP_open_type");
	pGeoIP_country_name_by_id = dlsym(ld, "GeoIP_country_name_by_id");
	pGeoIP_delete = dlsym(ld, "GeoIP_delete");
	pGeoIP_record_by_ipnum = dlsym(ld, "GeoIP_record_by_ipnum");
	pGeoIP_id_by_ipnum = dlsym(ld, "GeoIP_id_by_ipnum");
	pGeoIP_id_by_ipnum_v6 = dlsym(ld, "GeoIP_id_by_ipnum_v6");
	pGeoIP_record_by_ipnum_v6 = dlsym(ld, "GeoIP_record_by_ipnum_v6");
	pGeoIP_code_by_id = dlsym(ld, "GeoIP_code_by_id");

	if (pGeoIP_open_type == NULL || pGeoIP_country_name_by_id == NULL ||
	    pGeoIP_delete == NULL || pGeoIP_record_by_ipnum == NULL ||
	    pGeoIP_id_by_ipnum == NULL || pGeoIP_id_by_ipnum_v6 == NULL ||
	    pGeoIP_record_by_ipnum_v6 == NULL) {
		snprintf(err, sizeof(err), "ipcalc: could not find symbols in libGeoIP\n");
	    	ret = -1;
	    	goto exit;
	}

	ret = 0;
 exit:
	return ret;
}

# else

extern void _GeoIP_setup_dbfilename(void);
#  define p_GeoIP_setup_dbfilename _GeoIP_setup_dbfilename
#  define pGeoIP_open_type GeoIP_open_type
#  define pGeoIP_country_name_by_id GeoIP_country_name_by_id
#  define pGeoIP_delete GeoIP_delete
#  define pGeoIP_record_by_ipnum GeoIP_record_by_ipnum
#  define pGeoIP_id_by_ipnum GeoIP_id_by_ipnum
#  define pGeoIP_id_by_ipnum_v6 GeoIP_id_by_ipnum_v6
#  define pGeoIP_record_by_ipnum_v6 GeoIP_record_by_ipnum_v6
#  define pGeoIP_code_by_id GeoIP_code_by_id
# endif

static void geo_ipv4_lookup(struct in_addr ip, char **country, char **ccode, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup() != 0)
		return;

	ip.s_addr = ntohl(ip.s_addr);

	p_GeoIP_setup_dbfilename();

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum(gi, ip.s_addr);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = safe_strdup(p);

		p = pGeoIP_code_by_id(country_id);
		if (p)
			*ccode = safe_strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

		if (gir && gir->city)
			*city = safe_strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

			if (gir && gir->city)
				*city = safe_strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

static void geo_ipv6_lookup(struct in6_addr *ip, char **country, char **ccode, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup() != 0)
		return;

	p_GeoIP_setup_dbfilename();

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum_v6(gi, (geoipv6_t)*ip);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = safe_strdup(p);

		p = pGeoIP_code_by_id(country_id);
		if (p)
			*ccode = safe_strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

		if (gir && gir->city)
			*city = safe_strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0_V6, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

			if (gir && gir->city)
				*city = safe_strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char **coord)
{
        struct in_addr ipv4;
        struct in6_addr ipv6;
        if (inet_pton(AF_INET, ip, &ipv4) == 1) {
              geo_ipv4_lookup(ipv4, country, ccode, city, coord);
        } else if (inet_pton(AF_INET6, ip, &ipv6) == 1) {
              geo_ipv6_lookup(&ipv6, country, ccode, city, coord);
        }
        return;
}

#endif
