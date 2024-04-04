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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

int __attribute__((__format__(printf, 2, 3))) safe_asprintf(char **strp, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vasprintf(&(*strp), fmt, args);
	va_end(args);
	if (ret < 0) {
		fprintf(stderr, "Memory allocation failure\n");
		exit(1);
	}
	return ret;
}

int safe_atoi(const char *s, int *ret_i)
{
	char *x = NULL;
	long l;

	errno = 0;
	l = strtol(s, &x, 0);

	if (!x || x == s || *x || errno)
		return errno > 0 ? -errno : -EINVAL;

	if ((long)(int)l != l)
		return -ERANGE;

	*ret_i = (int)l;
	return 0;
}

/*!
  \fn char safe_strdup(const char *s)
  \brief strdup(3) that checks memory allocation or fail

  This function does the same as strdup(3) with additional memory allocation
  check.  When check fails the function will cause program to exit.

  \param string to be duplicated
  \return allocated duplicate
*/
extern char __attribute__((warn_unused_result)) *safe_strdup(const char *str)
{
	char *ret;

	if (!str)
		return NULL;

	ret = strdup(str);
	if (!ret) {
		fprintf(stderr, "Memory allocation failure\n");
		exit(1);
	}
	return ret;
}
