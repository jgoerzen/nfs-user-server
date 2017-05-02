/*
 * nfsmounted.c -- determine if a pathname has been NFS mounted
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Library Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#if defined(HAVE_UNISTD_H) || defined(STDC_HEADERS)
#include <unistd.h>
#endif
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef _POSIX_VERSION
#include <limits.h>			/* for PATH_MAX */
#else
#include <sys/param.h>			/* for MAXPATHLEN */
#endif
#include <errno.h>
#ifndef STDC_HEADERS
extern int errno;
#endif

#include <sys/stat.h>			/* for S_IFLNK */

#ifndef PATH_MAX
#ifdef _POSIX_VERSION
#define PATH_MAX _POSIX_PATH_MAX
#else
#ifdef MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 1024
#endif
#endif
#endif

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif
#ifdef MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif

int
nfsmounted(const char *path, struct stat *sbp)
{
#ifdef __linux__
	return major(sbp->st_dev) == 0;
#endif
	return 0;
}
