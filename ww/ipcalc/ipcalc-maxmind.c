/*
 * Copyright (c) 2018 Red Hat, Inc. All rights reserved.
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
 *   Martin Sehnoutka <msehnout@redhat.com>
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "ipcalc.h"

#ifdef USE_MAXMIND
#include <maxminddb.h>

#ifndef MAXMINDDB_LOCATION_COUNTRY
#define MAXMINDDB_LOCATION_COUNTRY "/usr/share/GeoIP/GeoLite2-Country.mmdb"
#endif

#ifndef MAXMINDDB_LOCATION_CITY
#define MAXMINDDB_LOCATION_CITY "/usr/share/GeoIP/GeoLite2-City.mmdb"
#endif

#ifdef USE_RUNTIME_LINKING
# include <dlfcn.h>
# define LIBNAME LIBPATH"/libmaxminddb.so.0"

typedef int (*MMDB_open_fn)
    (const char *const filename,
    uint32_t flags,
    MMDB_s *const mmdb);
typedef void (*MMDB_close_fn)
    (MMDB_s *const mmdb);
typedef MMDB_lookup_result_s (*MMDB_lookup_string_fn)
    (MMDB_s *const mmdb,
    const char *const ipstr,
    int *const gai_error,
    int *const mmdb_error);
typedef int (*MMDB_get_value_fn)
    (MMDB_entry_s *const start,
    MMDB_entry_data_s *const entry_data,
    ...);

static MMDB_close_fn          pMMDB_close;
static MMDB_get_value_fn      pMMDB_get_value;
static MMDB_lookup_string_fn  pMMDB_lookup_string;
static MMDB_open_fn           pMMDB_open;

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

    pMMDB_close         = dlsym(ld, "MMDB_close");
    pMMDB_get_value     = dlsym(ld, "MMDB_get_value");
    pMMDB_lookup_string = dlsym(ld, "MMDB_lookup_string");
    pMMDB_open          = dlsym(ld, "MMDB_open");

    if(pMMDB_close == NULL ||
       pMMDB_get_value == NULL ||
       pMMDB_lookup_string == NULL ||
       pMMDB_open == NULL) {
        snprintf(err, sizeof(err), "ipcalc: could not find symbols in libmaxmind\n");
        ret = -1;
        goto exit;
    }

	ret = 0;
 exit:
	return ret;
}

#else
#define pMMDB_close         MMDB_close
#define pMMDB_get_value     MMDB_get_value
#define pMMDB_lookup_string MMDB_lookup_string
#define pMMDB_open          MMDB_open
#endif

void process_result_from_mmdb_lookup(MMDB_entry_data_s *entry_data, int status, char **output)
{
    if (MMDB_SUCCESS == status) {
        if (entry_data->has_data) {
            if (entry_data->type == MMDB_DATA_TYPE_UTF8_STRING) {
                *output = (char *) calloc(entry_data->data_size + 1, sizeof(char));
                if (NULL != *output) {
                    memcpy(*output, entry_data->utf8_string, entry_data->data_size);
                } else {
                    fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
                }
            }
        }
    }
    /* Else fail silently */
}

void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char **coord)
{
    MMDB_s mmdb;
    MMDB_entry_data_s entry_data;
    int gai_error, mmdb_error, status, coordinates=0;
    double latitude = 0, longitude = 0;

    if (geo_setup() != 0)
        return;

    /* Open the system maxmind database with countries */
    status = pMMDB_open(MAXMINDDB_LOCATION_COUNTRY, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS == status) {
        /* Lookup IP address in the database */
        MMDB_lookup_result_s result = pMMDB_lookup_string(&mmdb, ip, &gai_error, &mmdb_error);
        if (MMDB_SUCCESS == mmdb_error) { 
            /* If the lookup was successfull and an entry was found */
            if (result.found_entry) {
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                /* Travel the path in the tree like structure of the MMDB and store the value if found */
                status = pMMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
                process_result_from_mmdb_lookup(&entry_data, status, country);
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                status = pMMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
                process_result_from_mmdb_lookup(&entry_data, status, ccode);
            }
        }
        /* Else fail silently */
        pMMDB_close(&mmdb);
    }
    /* Else fail silently */

    /* Open the system maxmind database with cities - which actually does not contain names of the cities */
    status = pMMDB_open(MAXMINDDB_LOCATION_CITY, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS == status) {
        /* Lookup IP address in the database */
        MMDB_lookup_result_s result = pMMDB_lookup_string(&mmdb, ip, &gai_error, &mmdb_error);
        if (MMDB_SUCCESS == mmdb_error) { 
            /* If the lookup was successfull and an entry was found */
            if (result.found_entry) {
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                // NOTE: Information about the city is not available in the free database, so there is not way
                // for me to implement this functionality right now, but it should be easy to add for anyone with
                // access to the paid databases.
                status = pMMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);
                if (MMDB_SUCCESS == status) {
                    if (entry_data.has_data) {
                        if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                            latitude = entry_data.double_value;
                            ++coordinates;
                        }
                    }
                }
                status = pMMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);
                if (MMDB_SUCCESS == status) {
                    if (entry_data.has_data) {
                        if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                            longitude = entry_data.double_value;
                            ++coordinates;
                        }
                    }
                }
                if (coordinates == 2) {
                    safe_asprintf(coord, "%f,%f", latitude, longitude);
                }
            }
        }
        /* Else fail silently */
        pMMDB_close(&mmdb);
    }
    /* Else fail silently */
}

#endif
